// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/irqdomain.h>
#include <linux/platform_device.h>
#include <linux/irqchip/riscv-imsic.h>

#include "../../../drivers/pci/pci.h"

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
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;
	struct platform_device *pdev;
	struct fwnode_handle *fn;
	struct resource *res;
	int ret;

	fn = irq_domain_alloc_named_id_fwnode("RISCV-APLIC", aplic->id);

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

	return 0;
}

void __init riscv_acpi_aplic_platform_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0);
}
