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
#include <linux/efi.h>
#include <linux/efi-bgrt.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/serial_core.h>

int acpi_noirq = 1;		/* skip ACPI IRQ initialization */
int acpi_disabled = 1;
EXPORT_SYMBOL(acpi_disabled);

int acpi_pci_disabled = 1;	/* skip ACPI PCI scan and IRQ initialization */
EXPORT_SYMBOL(acpi_pci_disabled);

static bool param_acpi_off __initdata;
static bool param_acpi_on __initdata;
static bool param_acpi_force __initdata;

static int __init parse_acpi(char *arg)
{
	if (!arg)
		return -EINVAL;

	/* "acpi=off" disables both ACPI table parsing and interpreter */
	if (strcmp(arg, "off") == 0)
		param_acpi_off = true;
	else if (strcmp(arg, "on") == 0) /* prefer ACPI over DT */
		param_acpi_on = true;
	else if (strcmp(arg, "force") == 0) /* force ACPI to be enabled */
		param_acpi_force = true;
	else
		return -EINVAL;	/* Core will print when we return error */

	return 0;
}
early_param("acpi", parse_acpi);

/*
 * acpi_fadt_sanity_check() - Check FADT presence and carry out sanity
 *			      checks on it
 *
 * Return 0 on success,  <0 on failure
 */
static int __init acpi_fadt_sanity_check(void)
{
	struct acpi_table_header *table;
	struct acpi_table_fadt *fadt;
	acpi_status status;
	int ret = 0;

	/*
	 * FADT is required on riscv; retrieve it to check its presence
	 * and carry out revision and ACPI HW reduced compliancy tests
	 */
	status = acpi_get_table(ACPI_SIG_FADT, 0, &table);
	if (ACPI_FAILURE(status)) {
		const char *msg = acpi_format_exception(status);

		pr_err("Failed to get FADT table, %s\n", msg);
		return -ENODEV;
	}

	fadt = (struct acpi_table_fadt *)table;

	if (!(fadt->flags & ACPI_FADT_HW_REDUCED)) {
		pr_err("FADT not ACPI hardware reduced compliant\n");
		ret = -EINVAL;
	}

	/*
	 * acpi_get_table() creates FADT table mapping that
	 * should be released after parsing and before resuming boot
	 */
	acpi_put_table(table);
	return ret;
}

/*
 * acpi_boot_table_init() called from setup_arch(), always.
 *	1. find RSDP and get its address, and then find XSDT
 *	2. extract all tables and checksums them all
 *	3. check ACPI FADT HW reduced flag
 *
 * We can parse ACPI boot-time tables such as MADT after
 * this function is called.
 *
 * On return ACPI is enabled if either:
 *
 * - ACPI tables are initialized and sanity checks passed
 * - acpi=force was passed in the command line and ACPI was not disabled
 *   explicitly through acpi=off command line parameter
 *
 * ACPI is disabled on function return otherwise
 */
void __init acpi_boot_table_init(void)
{
	/*
	 * Enable ACPI instead of device tree unless
	 * - ACPI has been disabled explicitly (acpi=off), or
	 * - firmware has not populated ACPI ptr in EFI system table
	 *   and ACPI has not been [force] enabled (acpi=on|force)
	 */
	if (param_acpi_off ||
	    (!param_acpi_on && !param_acpi_force &&
	     efi.acpi20 == EFI_INVALID_TABLE_ADDR))
		goto done;

	/*
	 * ACPI is disabled at this point. Enable it in order to parse
	 * the ACPI tables and carry out sanity checks
	 */
	enable_acpi();

	/*
	 * If ACPI tables are initialized and FADT sanity checks passed,
	 * leave ACPI enabled and carry on booting; otherwise disable ACPI
	 * on initialization error.
	 * If acpi=force was passed on the command line it forces ACPI
	 * to be enabled even if its initialization failed.
	 */
	if (acpi_table_init() || acpi_fadt_sanity_check()) {
		pr_err("Failed to init ACPI tables\n");
		if (!param_acpi_force)
			disable_acpi();
	}

done:
	if (acpi_disabled) {
		if (earlycon_acpi_spcr_enable)
			early_init_dt_scan_chosen_stdout();
	} else {
		acpi_parse_spcr(earlycon_acpi_spcr_enable, true);
		if (IS_ENABLED(CONFIG_ACPI_BGRT))
			acpi_table_parse(ACPI_SIG_BGRT, acpi_parse_bgrt);
	}
}

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
