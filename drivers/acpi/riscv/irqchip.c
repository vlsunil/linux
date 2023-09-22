// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

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

	pdev->dev.fwnode = imsic_acpi_get_fwnode();
	ret = platform_device_add(pdev);
	if (ret)
		platform_device_put(pdev);
}
