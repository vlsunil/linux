// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/irqchip/riscv-aplic.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/irqchip/riscv-imsic.h>
#include <asm/acpi.h>

#include "irq-riscv-aplic-main.h"

void aplic_irq_unmask(struct irq_data *d)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);

	writel(d->hwirq, priv->regs + APLIC_SETIENUM);
}

void aplic_irq_mask(struct irq_data *d)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);

	writel(d->hwirq, priv->regs + APLIC_CLRIENUM);
}

int aplic_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);
	void __iomem *sourcecfg;
	u32 val = 0;

	switch (type) {
	case IRQ_TYPE_NONE:
		val = APLIC_SOURCECFG_SM_INACTIVE;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		val = APLIC_SOURCECFG_SM_LEVEL_LOW;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		val = APLIC_SOURCECFG_SM_LEVEL_HIGH;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		val = APLIC_SOURCECFG_SM_EDGE_FALL;
		break;
	case IRQ_TYPE_EDGE_RISING:
		val = APLIC_SOURCECFG_SM_EDGE_RISE;
		break;
	default:
		return -EINVAL;
	}

	sourcecfg = priv->regs + APLIC_SOURCECFG_BASE;
	sourcecfg += (d->hwirq - 1) * sizeof(u32);
	writel(val, sourcecfg);

	return 0;
}

int aplic_irqdomain_translate(struct irq_fwspec *fwspec, u32 gsi_base,
			      unsigned long *hwirq, unsigned int *type)
{
	if (WARN_ON(fwspec->param_count < 2))
		return -EINVAL;
	if (WARN_ON(!fwspec->param[0]))
		return -EINVAL;

	/* For DT, gsi_base is always zero. */
	*hwirq = fwspec->param[0] - gsi_base;
	*type = fwspec->param[1] & IRQ_TYPE_SENSE_MASK;

	WARN_ON(*type == IRQ_TYPE_NONE);

	return 0;
}

void aplic_init_hw_global(struct aplic_priv *priv, bool msi_mode)
{
	u32 val;
#ifdef CONFIG_RISCV_M_MODE
	u32 valH;

	if (msi_mode) {
		val = lower_32_bits(priv->msicfg.base_ppn);
		valH = FIELD_PREP(APLIC_xMSICFGADDRH_BAPPN, upper_32_bits(priv->msicfg.base_ppn));
		valH |= FIELD_PREP(APLIC_xMSICFGADDRH_LHXW, priv->msicfg.lhxw);
		valH |= FIELD_PREP(APLIC_xMSICFGADDRH_HHXW, priv->msicfg.hhxw);
		valH |= FIELD_PREP(APLIC_xMSICFGADDRH_LHXS, priv->msicfg.lhxs);
		valH |= FIELD_PREP(APLIC_xMSICFGADDRH_HHXS, priv->msicfg.hhxs);
		writel(val, priv->regs + APLIC_xMSICFGADDR);
		writel(valH, priv->regs + APLIC_xMSICFGADDRH);
	}
#endif

	/* Setup APLIC domaincfg register */
	val = readl(priv->regs + APLIC_DOMAINCFG);
	val |= APLIC_DOMAINCFG_IE;
	if (msi_mode)
		val |= APLIC_DOMAINCFG_DM;
	writel(val, priv->regs + APLIC_DOMAINCFG);
	if (readl(priv->regs + APLIC_DOMAINCFG) != val)
		dev_warn(priv->dev, "unable to write 0x%x in domaincfg\n", val);
}

static void aplic_init_hw_irqs(struct aplic_priv *priv)
{
	int i;

	/* Disable all interrupts */
	for (i = 0; i <= priv->nr_irqs; i += 32)
		writel(-1U, priv->regs + APLIC_CLRIE_BASE + (i / 32) * sizeof(u32));

	/* Set interrupt type and default priority for all interrupts */
	for (i = 1; i <= priv->nr_irqs; i++) {
		writel(0, priv->regs + APLIC_SOURCECFG_BASE + (i - 1) * sizeof(u32));
		writel(APLIC_DEFAULT_PRIORITY,
		       priv->regs + APLIC_TARGET_BASE + (i - 1) * sizeof(u32));
	}

	/* Clear APLIC domaincfg */
	writel(0, priv->regs + APLIC_DOMAINCFG);
}

#ifdef CONFIG_ACPI

static struct aplic_priv *acpi_aplic_priv[32];
static u32 num_aplic;

struct fwnode_handle *find_aplic(u32 gsi)
{
	int i;

	/* Find the APLIC that manages this GSI. */
	for (i = 0; i < 32; i++) {
		struct aplic_priv *priv = acpi_aplic_priv[i];

		if (!priv)
			return NULL;

		if (gsi >= priv->gsi_base && gsi < (priv->gsi_base + priv->nr_irqs))
			return priv->dev->fwnode;
	}

	return NULL;
}

static int get_aplic_info(struct acpi_subtable_header *entry, u32 gsi_base,
			 u32 *nr_irqs, u32 *nr_idcs, u32 *aplic_id)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)entry;

	if (aplic->gsi_base != gsi_base)
		return 0;

	*nr_irqs = aplic->num_sources;
	*nr_idcs = aplic->num_idcs;
	*aplic_id = aplic->id;
	return 1;
}

static int parse_madt_aplic_entry(u32 gsi_base, u32 *nr_irqs, u32 *nr_idcs)
{
	struct acpi_subtable_header *hdr;
	unsigned long madt_end, entry;
	struct acpi_table_madt *madt;
	int aplic_id = -1;

	if (ACPI_FAILURE(acpi_get_table(ACPI_SIG_MADT, 0,
				(struct acpi_table_header **)&madt)))
		return aplic_id;

	entry = (unsigned long)madt;
	madt_end = entry + madt->header.length;

	/* Parse all entries looking for a match. */
	entry += sizeof(struct acpi_table_madt);
	while (entry + sizeof(struct acpi_subtable_header) < madt_end) {
		hdr = (struct acpi_subtable_header *)entry;
		if (hdr->type == ACPI_MADT_TYPE_APLIC &&
		    get_aplic_info(hdr, gsi_base, nr_irqs, nr_idcs, &aplic_id))
			break;
		else
			entry += hdr->length;
	}

	acpi_put_table((struct acpi_table_header *)madt);

	return aplic_id;
}

static const struct acpi_device_id aplic_acpi_match[] = {
	{ "RSCV0001", 0 },
	{}
};
MODULE_DEVICE_TABLE(acpi, aplic_acpi_match);

#endif

int aplic_setup_priv(struct aplic_priv *priv, struct device *dev, void __iomem *regs)
{
	struct of_phandle_args parent;
	int rc;

	/* Save device pointer and register base */
	priv->dev = dev;
	priv->regs = regs;

	if (is_of_node(dev->fwnode)) {
		/* Find out number of interrupt sources */
		rc = of_property_read_u32(to_of_node(dev->fwnode), "riscv,num-sources",
						     &priv->nr_irqs);
		if (rc) {
			dev_err(dev, "failed to get number of interrupt sources\n");
			return rc;
		}

		/*
		 * Find out number of IDCs based on parent interrupts
		 *
		 * If "msi-parent" property is present then we ignore the
		 * APLIC IDCs which forces the APLIC driver to use MSI mode.
		 */
		if (!of_property_present(to_of_node(dev->fwnode), "msi-parent")) {
			while (!of_irq_parse_one(to_of_node(dev->fwnode), priv->nr_idcs, &parent))
				priv->nr_idcs++;
		}
	} else {
		u64 gsi_base;
		u32 id, nr_irqs, nr_idcs;
		acpi_status status;

		if (!acpi_has_method(ACPI_HANDLE(dev), "_GSB"))
			return -1;

		status = acpi_evaluate_integer(ACPI_HANDLE(dev), "_GSB", NULL, &gsi_base);
		if (ACPI_FAILURE(status)) {
			acpi_handle_err(ACPI_HANDLE(dev), "failed to evaluate _GSB method\n");
				return -1;
		}

		id = parse_madt_aplic_entry((u32)gsi_base, &nr_irqs, &nr_idcs);
		if (id < 0) {
			dev_err(dev, "failed to find APLIC in MADT\n");
			return -1;
		}
		priv->gsi_base = (u32)gsi_base;
		priv->nr_irqs = nr_irqs;
		priv->nr_idcs = nr_idcs;
		priv->id = id;
	}

#ifdef CONFIG_ACPI
	acpi_aplic_priv[num_aplic++] = priv;
#endif
	/* Setup initial state APLIC interrupts */
	aplic_init_hw_irqs(priv);

	return 0;
}

static int aplic_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	bool msi_mode = false;
	void __iomem *regs;
	int rc;

pr_info("aplic_probe: ENTER\n");
	/* Map the MMIO registers */
	regs = devm_platform_ioremap_resource(pdev, 0);
	if (!regs) {
		dev_err(dev, "failed map MMIO registers\n");
		return -ENOMEM;
	}

	/*
	 * If msi-parent property is present then setup APLIC MSI
	 * mode otherwise setup APLIC direct mode.
	 */
	if (is_of_node(dev->fwnode))
		msi_mode = of_property_present(to_of_node(dev->fwnode), "msi-parent");
	else
		msi_mode = imsic_acpi_get_fwnode(NULL) ? 1 : 0;

	if (msi_mode)
		rc = aplic_msi_setup(dev, regs);
	else
		rc = aplic_direct_setup(dev, regs);
	if (rc)
		dev_err(dev, "failed to setup APLIC in %s mode\n", msi_mode ? "MSI" : "direct");

	return rc;
}

static const struct of_device_id aplic_match[] = {
	{ .compatible = "riscv,aplic" },
	{}
};

static struct platform_driver aplic_driver = {
	.driver = {
		.name		= "riscv-aplic",
		.of_match_table	= aplic_match,
		.acpi_match_table = ACPI_PTR(aplic_acpi_match),
	},
	.probe = aplic_probe,
};
builtin_platform_driver(aplic_driver);
