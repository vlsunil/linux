// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/sort.h>
#include <linux/irq.h>

static int irqchip_cmp_func(const void *in0, const void *in1)
{
	struct acpi_probe_entry *elem0 = (struct acpi_probe_entry *)in0;
	struct acpi_probe_entry *elem1 = (struct acpi_probe_entry *)in1;

	return (elem0->type > elem1->type) - (elem0->type < elem1->type);
}

/*
 * RISC-V irqchips in MADT of ACPI spec are defined in the same order how
 * they should be probed. Since IRQCHIP_ACPI_DECLARE doesn't define any
 * order, this arch function will reorder the probe functions as per the
 * required order for the architecture.
 */
void arch_sort_irqchip_probe(struct acpi_probe_entry *ap_head, int nr)
{
	struct acpi_probe_entry *ape = ap_head;

	if (nr == 1 || !ACPI_COMPARE_NAMESEG(ACPI_SIG_MADT, ape->id))
		return;
	sort(ape, nr, sizeof(*ape), irqchip_cmp_func, NULL);
}

struct riscv_ext_intc_list {
	struct fwnode_handle *fwnode;
	u32 gsi_base;
	u32 nr_irqs;
	u32 id;
	u32 type;
	struct list_head list;
};

LIST_HEAD(ext_intc_list);

struct fwnode_handle *riscv_acpi_get_gsi_domain_id(u32 gsi)
{
	struct riscv_ext_intc_list *ext_intc_element;
	struct list_head *i, *tmp;

	list_for_each_safe(i, tmp, &ext_intc_list) {
		ext_intc_element = list_entry(i, struct riscv_ext_intc_list, list);
		if (gsi >= ext_intc_element->gsi_base &&
		    gsi < (ext_intc_element->gsi_base + ext_intc_element->nr_irqs))
			return ext_intc_element->fwnode;
	}

	return NULL;
}

int riscv_acpi_register_ext_intc(struct fwnode_handle *fwnode, u32 gsi_base, u32 nr_irqs,
				 u32 id, u32 type)
{
	struct riscv_ext_intc_list *ext_intc_element;

	ext_intc_element = kzalloc(sizeof(*ext_intc_element), GFP_KERNEL);
	if (!ext_intc_element)
		return -1;

	ext_intc_element->fwnode = fwnode;
	ext_intc_element->gsi_base = gsi_base;
	ext_intc_element->nr_irqs = nr_irqs;
	ext_intc_element->id = id;
	list_add_tail(&ext_intc_element->list, &ext_intc_list);
	return 0;
}
