// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/smp.h>

#include "irq-riscv-imsic-state.h"

static int imsic_cpu_page_phys(unsigned int cpu,
			       unsigned int guest_index,
			       phys_addr_t *out_msi_pa)
{
	struct imsic_global_config *global;
	struct imsic_local_config *local;

	global = &imsic->global;
	local = per_cpu_ptr(global->local, cpu);

	if (BIT(global->guest_index_bits) <= guest_index)
		return -EINVAL;

	if (out_msi_pa)
		*out_msi_pa = local->msi_pa +
			      (guest_index * IMSIC_MMIO_PAGE_SZ);

	return 0;
}

static int imsic_get_cpu(const struct cpumask *mask_val, bool force,
			 unsigned int *out_target_cpu)
{
	unsigned int cpu;

	if (force)
		cpu = cpumask_first(mask_val);
	else
		cpu = cpumask_any_and(mask_val, cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	if (out_target_cpu)
		*out_target_cpu = cpu;

	return 0;
}

static void imsic_irq_mask(struct irq_data *d)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	bitmap_clear(imsic->ids_enabled_bimap, d->hwirq, 1);
	__imsic_id_disable(d->hwirq);
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);

	imsic_ids_remote_sync();
}

static void imsic_irq_unmask(struct irq_data *d)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	bitmap_set(imsic->ids_enabled_bimap, d->hwirq, 1);
	__imsic_id_enable(d->hwirq);
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);

	imsic_ids_remote_sync();
}

static void imsic_irq_compose_msi_msg(struct irq_data *d,
				      struct msi_msg *msg)
{
	phys_addr_t msi_addr;
	unsigned int cpu;
	int err;

	cpu = imsic_id_get_target(d->hwirq);
	if (WARN_ON(cpu == UINT_MAX))
		return;

	err = imsic_cpu_page_phys(cpu, 0, &msi_addr);
	if (WARN_ON(err))
		return;

	msg->address_hi = upper_32_bits(msi_addr);
	msg->address_lo = lower_32_bits(msi_addr);
	msg->data = d->hwirq;
}

#ifdef CONFIG_SMP
static int imsic_irq_set_affinity(struct irq_data *d,
				  const struct cpumask *mask_val,
				  bool force)
{
	unsigned int target_cpu;
	int rc;

	rc = imsic_get_cpu(mask_val, force, &target_cpu);
	if (rc)
		return rc;

	imsic_id_set_target(d->hwirq, target_cpu);
	irq_data_update_effective_affinity(d, cpumask_of(target_cpu));

	return IRQ_SET_MASK_OK;
}
#endif

static struct irq_chip imsic_irq_base_chip = {
	.name			= "IMSIC-BASE",
	.irq_mask		= imsic_irq_mask,
	.irq_unmask		= imsic_irq_unmask,
#ifdef CONFIG_SMP
	.irq_set_affinity	= imsic_irq_set_affinity,
#endif
	.irq_compose_msi_msg	= imsic_irq_compose_msi_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_MASK_ON_SUSPEND,
};

static int imsic_irq_domain_alloc(struct irq_domain *domain,
				  unsigned int virq,
				  unsigned int nr_irqs,
				  void *args)
{
	int i, hwirq, err = 0;
	unsigned int cpu;

	err = imsic_get_cpu(cpu_online_mask, false, &cpu);
	if (err)
		return err;

	hwirq = imsic_ids_alloc(get_count_order(nr_irqs));
	if (hwirq < 0)
		return hwirq;

	for (i = 0; i < nr_irqs; i++) {
		imsic_id_set_target(hwirq + i, cpu);
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &imsic_irq_base_chip, imsic,
				    handle_simple_irq, NULL, NULL);
		irq_set_noprobe(virq + i);
		irq_set_affinity(virq + i, cpu_online_mask);
		/*
		 * IMSIC does not implement irq_disable() so Linux interrupt
		 * subsystem will take a lazy approach for disabling an IMSIC
		 * interrupt. This means IMSIC interrupts are left unmasked
		 * upon system suspend and interrupts are not processed
		 * immediately upon system wake up. To tackle this, we disable
		 * the lazy approach for all IMSIC interrupts.
		 */
		irq_set_status_flags(virq + i, IRQ_DISABLE_UNLAZY);
	}

	return 0;
}

static void imsic_irq_domain_free(struct irq_domain *domain,
				  unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);

	imsic_ids_free(d->hwirq, get_count_order(nr_irqs));
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops imsic_base_domain_ops = {
	.alloc		= imsic_irq_domain_alloc,
	.free		= imsic_irq_domain_free,
};

#ifdef CONFIG_RISCV_IMSIC_PCI

static void imsic_pci_mask_irq(struct irq_data *d)
{
	pci_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void imsic_pci_unmask_irq(struct irq_data *d)
{
	pci_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip imsic_pci_irq_chip = {
	.name			= "IMSIC-PCI",
	.irq_mask		= imsic_pci_mask_irq,
	.irq_unmask		= imsic_pci_unmask_irq,
	.irq_eoi		= irq_chip_eoi_parent,
};

static struct msi_domain_ops imsic_pci_domain_ops = {
};

static struct msi_domain_info imsic_pci_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_PCI_MSIX | MSI_FLAG_MULTI_PCI_MSI),
	.ops	= &imsic_pci_domain_ops,
	.chip	= &imsic_pci_irq_chip,
};

#endif

static struct irq_chip imsic_plat_irq_chip = {
	.name			= "IMSIC-PLAT",
};

static struct msi_domain_ops imsic_plat_domain_ops = {
};

static struct msi_domain_info imsic_plat_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS),
	.ops	= &imsic_plat_domain_ops,
	.chip	= &imsic_plat_irq_chip,
};

static int imsic_irq_domains_init(struct fwnode_handle *fwnode)
{
	/* Create Base IRQ domain */
	imsic->base_domain = irq_domain_create_tree(fwnode,
					&imsic_base_domain_ops, imsic);
	if (!imsic->base_domain) {
		pr_err("%pfwP: failed to create IMSIC base domain\n", fwnode);
		return -ENOMEM;
	}
	irq_domain_update_bus_token(imsic->base_domain, DOMAIN_BUS_NEXUS);

#ifdef CONFIG_RISCV_IMSIC_PCI
	/* Create PCI MSI domain */
	imsic->pci_domain = pci_msi_create_irq_domain(fwnode,
						&imsic_pci_domain_info,
						imsic->base_domain);
	if (!imsic->pci_domain) {
		pr_err("%pfwP: failed to create IMSIC PCI domain\n", fwnode);
		irq_domain_remove(imsic->base_domain);
		return -ENOMEM;
	}
#endif

	/* Create Platform MSI domain */
	imsic->plat_domain = platform_msi_create_irq_domain(fwnode,
						&imsic_plat_domain_info,
						imsic->base_domain);
	if (!imsic->plat_domain) {
		pr_err("%pfwP: failed to create IMSIC platform domain\n", fwnode);
		if (imsic->pci_domain)
			irq_domain_remove(imsic->pci_domain);
		irq_domain_remove(imsic->base_domain);
		return -ENOMEM;
	}

	return 0;
}

static int imsic_platform_probe_common(struct fwnode_handle *fwnode)
{
	struct imsic_global_config *global;
	int rc;

	if (!imsic) {
		pr_err("%pfwP: early driver not probed\n", fwnode);
		return -ENODEV;
	}

	if (imsic->base_domain) {
		pr_err("%pfwP: irq domain already created\n", fwnode);
		return -ENODEV;
	}

	global = &imsic->global;

	/* Initialize IRQ and MSI domains */
	rc = imsic_irq_domains_init(fwnode);
	if (rc) {
		pr_err("%pfwP: failed to initialize IRQ and MSI domains\n", fwnode);
		return rc;
	}

	pr_info("%pfwP: hart-index-bits: %d,  guest-index-bits: %d\n", fwnode,
		 global->hart_index_bits, global->guest_index_bits);
	pr_info("%pfwP: group-index-bits: %d, group-index-shift: %d\n", fwnode,
		 global->group_index_bits, global->group_index_shift);
	pr_info("%pfwP: mapped %d interrupts at base PPN %pa\n", fwnode,
		 global->nr_ids, &global->base_addr);

	return 0;
}

static int imsic_platform_dt_probe(struct platform_device *pdev)
{
	return imsic_platform_probe_common(pdev->dev.fwnode);
}

static const struct of_device_id imsic_platform_match[] = {
	{ .compatible = "riscv,imsics" },
	{}
};

static struct platform_driver imsic_platform_driver = {
	.driver = {
		.name		= "riscv-imsic",
		.of_match_table	= imsic_platform_match,
	},
	.probe = imsic_platform_dt_probe,
};
builtin_platform_driver(imsic_platform_driver);

#ifdef CONFIG_ACPI

/*
 *  On ACPI based systems, PCI enumeration happens early during boot in
 *  acpi_scan_init(). PCI enumeration expects MSI domain setup before
 *  it calls pci_set_msi_domain(). Hence, unlike in DT where
 *  imsic-platform drive probe happens late during boot, ACPI based
 *  systems need to setup the MSI domain early.
 */
int imsic_platform_acpi_probe(struct fwnode_handle *fwnode)
{
	return imsic_platform_probe_common(fwnode);
}

#endif
