// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/platform_device.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqchip/riscv-aplic.h>

#include "../../../drivers/pci/pci.h"

static int nr_plics = 0;

static struct
{
	struct fwnode_handle *fwnode;
	u32 gsi_base;
	u16 num_sources;
} plic_acpi_data[MAX_PLICS];

struct fwnode_handle *riscv_acpi_get_gsi_domain_id(u32 gsi)
{
	int i;
	struct fwnode_handle *fn;

	fn = aplic_get_fwnode(gsi);
	if (fn)
		return fn;

	/* Find the PLIC that manages this GSI. */
	for (i = 0; i < nr_plics; i++) {
		if (gsi >= plic_acpi_data[i].gsi_base &&
		    gsi <= (plic_acpi_data[i].gsi_base + plic_acpi_data[i].num_sources)) {
			return plic_acpi_data[i].fwnode;
		}
	}
pr_info("riscv_acpi_get_gsi_domain_id: returning INTC for GSI %d\n", gsi);
	return riscv_get_intc_hwnode();
}

u32 riscv_acpi_gsi_to_irq(u32 gsi)
{
	return acpi_register_gsi(NULL, gsi, ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
}

void __init riscv_acpi_imsic_platform_init(void)
{
	struct platform_device *pdev;
	int ret;

	if (!imsic_acpi_get_fwnode(NULL)) {
		pci_no_msi();
		return;
	}

	pdev = platform_device_alloc("riscv-imsic", 0);
	if (!pdev)
		return;

	pdev->dev.fwnode = imsic_acpi_get_fwnode(NULL);
	ret = platform_device_add(pdev);
	if (ret)
		platform_device_put(pdev);
}


static int __init aplic_parse_madt(union acpi_subtable_headers *header,
				   const unsigned long end)
{
#if 0
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;
	/* Cache APLIC info for GSI conversion */
	aplic_acpi_data[nr_aplics].gsi_base = aplic->gsi_base;
	aplic_acpi_data[nr_aplics].num_sources = aplic->num_sources;
	aplic_acpi_data[nr_aplics].fwnode = fn;
	nr_aplics++;

	struct platform_device *pdev;
	struct fwnode_handle *fn;
	struct resource *res;
	int ret;

	fn = irq_domain_alloc_named_id_fwnode("RISCV-APLIC", aplic->id);

	/* Cache APLIC info for GSI conversion */
	aplic_acpi_data[nr_aplics].gsi_base = aplic->gsi_base;
	aplic_acpi_data[nr_aplics].num_sources = aplic->num_sources;
	aplic_acpi_data[nr_aplics].fwnode = fn;
	nr_aplics++;

	pdev = platform_device_alloc("riscv-aplic", aplic->id);
	if (!pdev)
		return -ENOMEM;

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res) {
		platform_device_put(pdev);
		return -ENOMEM;
	}

	res->start = aplic->base_addr;
	res->end = res->start + aplic->size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	/*
	 * Add copy of aplic pointer so that platform driver get aplic details.
	 */
	ret = platform_device_add_data(pdev, &header, sizeof(header));
	if (ret) {
		platform_device_put(pdev);
		return ret;
	}

	pdev->dev.fwnode = fn;
	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		return ret;
	}

#endif
	return 0;
}

void __init riscv_acpi_aplic_platform_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0);
}

static int __init plic_parse_madt(union acpi_subtable_headers *header,
				  const unsigned long end)
{
	struct acpi_madt_plic *plic = (struct acpi_madt_plic *)header;
	struct platform_device *pdev;
	struct fwnode_handle *fn;
	struct resource *res;
	int ret;

	fn = irq_domain_alloc_named_id_fwnode("RISCV-PLIC", plic->id);

	/* Cache APLIC info for GSI conversion */
	plic_acpi_data[nr_plics].gsi_base = plic->gsi_base;
	plic_acpi_data[nr_plics].num_sources = plic->num_irqs;
	plic_acpi_data[nr_plics].fwnode = fn;
	nr_plics++;

	pdev = platform_device_alloc("riscv-plic", plic->id);
	if (!pdev)
		return -ENOMEM;

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res) {
		platform_device_put(pdev);
		return -ENOMEM;
	}

	res->start = plic->base_addr;
	res->end = res->start + plic->size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	/*
	 * Add copy of plic pointer so that platform driver get plic details.
	 */
	ret = platform_device_add_data(pdev, &plic, sizeof(plic));
	if (ret) {
		platform_device_put(pdev);
		return ret;
	}

	pdev->dev.fwnode = fn;
	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		return ret;
	}

	return 0;
}

void __init riscv_acpi_plic_platform_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_PLIC, plic_parse_madt, 0);
}
