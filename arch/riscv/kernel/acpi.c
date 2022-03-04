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
 *  Copyright (C) 2021, Ventana Micro Systems Inc.
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#define pr_fmt(fmt) "ACPI: " fmt

#include <linux/acpi.h>
#include <linux/cpumask.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/irq_work.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/smp.h>
#include <linux/serial_core.h>
#include <linux/pgtable.h>

#include <acpi/ghes.h>
#include <asm/cputype.h>
#include <asm/cpu_ops.h>
#include <asm/smp_plat.h>

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
 * __acpi_map_table() will be called before page_init(), so early_ioremap()
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

	/*
	 * Revision in table header is the FADT Major revision, and there
	 * is a minor revision of FADT which was introduced by ACPI 5.1,
	 * we only deal with ACPI 5.1 or newer revision to get GIC and SMP
	 * boot protocol configuration data.
	 */
	if (table->revision < ACPI_TABLE_FADT_MAJOR_REVISION ||
	   (table->revision == ACPI_TABLE_FADT_MAJOR_REVISION &&
		fadt->minor_revision < ACPI_TABLE_FADT_MINOR_REVISION)) {
		pr_err(FW_BUG "Unsupported FADT revision %d.%d, should be 5.1+\n",
		       table->revision, fadt->minor_revision);
			ret = -EINVAL;
			goto out;
	}

	if (!(fadt->flags & ACPI_FADT_HW_REDUCED)) {
		pr_err("FADT not ACPI hardware reduced compliant\n");
		ret = -EINVAL;
	}

out:
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
 *	3. check ACPI FADT revision
 *	4. check ACPI FADT HW reduced flag
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
	 * - the device tree is not empty (it has more than just a /chosen node,
	 *   and a /hypervisor node when running on Xen)
	 *   and ACPI has not been [force] enabled (acpi=on|force)
	 */

	/*
	 * if (param_acpi_off ||
	 *    (!param_acpi_on && !param_acpi_force &&
	 *     of_scan_flat_dt(dt_scan_depth1_nodes, NULL)))
	 *     goto done;
	 */

	if (param_acpi_off || (efi.acpi20 == EFI_INVALID_TABLE_ADDR))
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

pgprot_t __acpi_get_mem_attribute(phys_addr_t addr)
{
	return PAGE_KERNEL;
}

void __iomem *acpi_os_ioremap(acpi_physical_address phys, acpi_size size)
{
	efi_memory_desc_t *md, *region = NULL;
	pgprot_t prot;

	if (WARN_ON_ONCE(!efi_enabled(EFI_MEMMAP)))
		return NULL;

	for_each_efi_memory_desc(md) {
		u64 end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

		if (phys < md->phys_addr || phys >= end)
			continue;

		if (phys + size > end) {
			pr_warn(FW_BUG "requested region covers multiple EFI memory regions\n");
			return NULL;
		}
		region = md;
		break;
	}

	/*
	 * It is fine for AML to remap regions that are not represented in the
	 * EFI memory map at all, as it only describes normal memory, and MMIO
	 * regions that require a virtual mapping to make them accessible to
	 * the EFI runtime services.
	 */
	prot = PAGE_KERNEL;
	if (region) {
		switch (region->type) {
		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA:
		case EFI_CONVENTIONAL_MEMORY:
		case EFI_PERSISTENT_MEMORY:
			if (memblock_is_map_memory(phys) ||
			    !memblock_is_region_memory(phys, size)) {
				pr_warn(FW_BUG "requested region covers kernel memory @ %pa\n",
					&phys);
				return NULL;
			}
			/*
			 * Mapping kernel memory is permitted if the region in
			 * question is covered by a single memblock with the
			 * NOMAP attribute set: this enables the use of ACPI
			 * table overrides passed via initramfs, which are
			 * reserved in memory using arch_reserve_mem_area()
			 * below. As this particular use case only requires
			 * read access.
			 */
			fallthrough;

		case EFI_RUNTIME_SERVICES_CODE:
			/*
			 * This would be unusual, but not problematic per se,
			 * as long as we take care not to create a writable
			 * mapping for executable code.
			 */
			prot = PAGE_KERNEL_READ;
			break;

		case EFI_ACPI_RECLAIM_MEMORY:
			/*
			 * ACPI reclaim memory is used to pass firmware tables
			 * and other data that is intended for consumption by
			 * the OS only, which may decide it wants to reclaim
			 * that memory and use it for something else. We never
			 * do that, but we usually add it to the linear map
			 * anyway, in which case we should use the existing
			 * mapping.
			 */
			if (memblock_is_map_memory(phys))
				return (void __iomem *)__phys_to_virt(phys);
			fallthrough;

		default:
				prot = PAGE_KERNEL;
		}
	}
	return __ioremap(phys, size, prot);
}
void __init arch_reserve_mem_area(acpi_physical_address addr, size_t size)
{
	memblock_mark_nomap(addr, size);
}
