// SPDX-License-Identifier: GPL-2.0-only
/*
 *  RISC-V Specific Low-Level ACPI Boot Support
 *
 *  Copyright (C) 2013-2014, Linaro Ltd.
 *	Author: Al Stone <al.stone@linaro.org>
 *	Author: Graeme Gregory <graeme.gregory@linaro.org>
 *	Author: Hanjun Guo <hanjun.guo@linaro.org>
 *	Author: Tomasz Nowicki <tomasz.nowicki@linaro.org>
 *	Author: Naresh Bhat <naresh.bhat@linaro.org>
 *
 *  Copyright (C) 2021-2023, Ventana Micro Systems Inc.
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>

int acpi_noirq = 1;		/* skip ACPI IRQ initialization */
int acpi_disabled = 1;
EXPORT_SYMBOL(acpi_disabled);

int acpi_pci_disabled = 1;	/* skip ACPI PCI scan and IRQ initialization */
EXPORT_SYMBOL(acpi_pci_disabled);

#ifndef CONFIG_SMP
static struct acpi_madt_rintc boot_cpu_madt_rintc;

struct acpi_madt_rintc *acpi_bootcpu_get_madt_rintc(int cpu)
{
	struct acpi_table_madt *madt = NULL;
	unsigned long madt_end, entry;
	static bool rintc_found = FALSE;

	if (rintc_found)
		return &boot_cpu_madt_rintc;

	acpi_get_table(ACPI_SIG_MADT, 0,
		       (struct acpi_table_header **)&madt);
	if (!madt)
		return NULL;

	entry = (unsigned long)madt;
	madt_end = entry + madt->header.length;

	/* Parse all entries looking for a match. */

	entry += sizeof(struct acpi_table_madt);
	while (entry + sizeof(struct acpi_subtable_header) < madt_end) {
		struct acpi_subtable_header *header =
			(struct acpi_subtable_header *)entry;
		if (header->type == ACPI_MADT_TYPE_RINTC) {
			boot_cpu_madt_rintc = *(struct acpi_madt_rintc *)header;
			acpi_put_table((struct acpi_table_header *)madt);
			rintc_found = TRUE;
			return &boot_cpu_madt_rintc;
		}
		entry += header->length;
	}
	acpi_put_table((struct acpi_table_header *)madt);
	return NULL;
}
#endif

/*
 * __acpi_map_table() will be called before paging_init(), so early_ioremap()
 * or early_memremap() should be called here to for ACPI table mapping.
 */
void __init __iomem *__acpi_map_table(unsigned long phys, unsigned long size)
{
	if (!size)
		return NULL;

	return early_memremap(phys, size);
}

void __init __acpi_unmap_table(void __iomem *map, unsigned long size)
{
	if (!map || !size)
		return;

	early_memunmap(map, size);
}

void *acpi_os_ioremap(acpi_physical_address phys, acpi_size size)
{
	return memremap(phys, size, MEMREMAP_WB);
}

#ifdef CONFIG_PCI

int raw_pci_read(unsigned int domain, unsigned int bus, unsigned int devfn,
		 int reg, int len, u32 *val)
{
	return gen_raw_pci_read(domain, bus, devfn, reg, len, val);
}

int raw_pci_write(unsigned int domain, unsigned int bus, unsigned int devfn,
		  int reg, int len, u32 val)
{
	return gen_raw_pci_write(domain, bus, devfn, reg, len, val);
}

int acpi_pci_bus_find_domain_nr(struct pci_bus *bus)
{
	return gen_acpi_pci_bus_find_domain_nr(bus);
}

struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
{
	return gen_pci_acpi_scan_root(root);
}
#endif	/* CONFIG_PCI */
