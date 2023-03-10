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
#include <linux/efi.h>
#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>
#include <linux/irqchip/riscv-aplic.h>
#include <linux/platform_device.h>
#include <linux/msi.h>

int acpi_noirq = 1;		/* skip ACPI IRQ initialization */
int acpi_disabled = 1;
EXPORT_SYMBOL(acpi_disabled);

int acpi_pci_disabled = 1;	/* skip ACPI PCI scan and IRQ initialization */
EXPORT_SYMBOL(acpi_pci_disabled);

static struct acpi_madt_rintc cpu_madt_rintc[NR_CPUS];
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

	/*
	 * The revision in the table header is the FADT's Major revision. The
	 * FADT also has a minor revision, which is stored in the FADT itself.
	 *
	 * TODO: Currently, we check for 6.5 as the minimum version to check
	 * for HW_REDUCED flag. However, once RISC-V updates are released in
	 * the ACPI spec, we need to update this check for exact minor revision
	 */
	if (table->revision < 6 || (table->revision == 6 && fadt->minor_revision < 5)) {
		pr_err(FW_BUG "Unsupported FADT revision %d.%d, should be 6.5+\n",
		       table->revision, fadt->minor_revision);
	}

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
		return;

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
}

static int acpi_parse_madt_rintc(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_rintc *rintc = (struct acpi_madt_rintc *)header;
	int cpuid;

	if (!(rintc->flags & ACPI_MADT_ENABLED))
		return 0;

	cpuid = riscv_hartid_to_cpuid(rintc->hart_id);
	/*
	 * When CONFIG_SMP is disabled, mapping won't be created for
	 * all cpus.
	 * CPUs more than NR_CPUS, will be ignored.
	 */
	if (cpuid >= 0 && cpuid < NR_CPUS)
		cpu_madt_rintc[cpuid] = *rintc;

	return 0;
}

static int acpi_init_rintc_array(void)
{
	if (acpi_table_parse_madt(ACPI_MADT_TYPE_RINTC, acpi_parse_madt_rintc, 0) > 0)
		return 0;

	return -ENODEV;
}

/*
 * Instead of parsing (and freeing) the ACPI table, cache
 * the RINTC structures since they are frequently used
 * like in  cpuinfo.
 */
struct acpi_madt_rintc *acpi_cpu_get_madt_rintc(int cpu)
{
	static bool rintc_init_done;

	if (!rintc_init_done) {
		if (acpi_init_rintc_array()) {
			pr_err("No valid RINTC entries exist\n");
			return NULL;
		}

		rintc_init_done = true;
	}

	return &cpu_madt_rintc[cpu];
}

u32 get_acpi_id_for_cpu(int cpu)
{
	struct acpi_madt_rintc *rintc = acpi_cpu_get_madt_rintc(cpu);

	BUG_ON(!rintc);

	return rintc->uid;
}

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

static int __init aplic_parse_madt(union acpi_subtable_headers *header,
				   const unsigned long end)
{
	struct acpi_madt_aplic *aplic_entry = (struct acpi_madt_aplic *)header;
	struct aplic_plat_data plat_data;
	struct platform_device *pdev;
	struct irq_domain *msi_domain;
	struct fwnode_handle *fwnode;
	struct resource *res;
	int ret;

	pdev = platform_device_alloc("riscv-aplic", aplic_entry->id);
	if (!pdev)
		return -ENOMEM;

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res) {
		ret = -ENOMEM;
		goto dev_put;
	}

	res->start = aplic_entry->base_addr;
	res->end = aplic_entry->base_addr +
				aplic_entry->size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	plat_data.nr_idcs = aplic_entry->num_idcs;
	plat_data.gsi_base = aplic_entry->gsi_base;
	plat_data.nr_irqs = aplic_entry->num_irqs;
	plat_data.aplic_id = aplic_entry->id;
	ret = platform_device_add_data(pdev, &plat_data, sizeof(plat_data));

	if (ret)
		goto dev_put;

	fwnode = irq_domain_alloc_named_id_fwnode("riscv-aplic", aplic_entry->id);
	if (!fwnode)
		goto dev_put;

	pdev->dev.fwnode = fwnode;
	msi_domain = platform_acpi_msi_domain(&pdev->dev);
	if (msi_domain)
		dev_set_msi_domain(&pdev->dev, msi_domain);

	ret = platform_device_add(pdev);
	if (ret)
		goto dev_put;
	return 0;

dev_put:
	if (res)
		kfree(res);

	if (pdev->dev.fwnode)
		irq_domain_free_fwnode(pdev->dev.fwnode);

	platform_device_put(pdev);

	return ret;
}

static void riscv_acpi_aplic_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0);
}

void acpi_arch_device_init(void)
{
	riscv_acpi_aplic_init();
}

/*
 * For PLIC, the ext_intc_id format is as follows:
 * Bits [31:24] PLIC ID
 * Bits [15:0] PLIC S-Mode Context ID for this hart
 */
#define PLIC_ID(x) (x >> 24)
#define CONTEXT_ID(x) (x & 0x0000ffff)

int acpi_get_ext_intc_parent_hartid(u32 ext_intc_id, int idx, bool aplic, unsigned long *hartid)
{
	int cpu, i = 0;;

	for_each_possible_cpu(cpu) {
		u32 id = cpu_madt_rintc[cpu].ext_intc_id;

		if (!aplic)
			id = PLIC_ID(id);

		if (id == ext_intc_id) {
			if (i == idx) {
				*hartid = cpu_madt_rintc[cpu].hart_id;
				return 0;
			}
			i++;
		}
	}

	return -1;
}

int acpi_get_plic_nr_contexts(u8 plic_id)
{
	int cpuid, nr_contexts = 0;

	for_each_possible_cpu(cpuid) {
		u32 id = cpu_madt_rintc[cpuid].ext_intc_id;

		if (cpu_madt_rintc[cpuid].version != 0 && PLIC_ID(id) == plic_id)
			nr_contexts++;
	}

	return nr_contexts;
}

int acpi_get_plic_context_id(u8 plic_id, u16 idx)
{
	int cpuid, nr_contexts = -1;

	for_each_possible_cpu(cpuid) {
		u32 id = cpu_madt_rintc[cpuid].ext_intc_id;

		if (cpu_madt_rintc[cpuid].version != 0 && PLIC_ID(id) == plic_id)
			nr_contexts++;

		if (nr_contexts == idx)
			return CONTEXT_ID(id);
	}

	return -1;
}

#ifdef CONFIG_PCI

/*
 * raw_pci_read/write - Platform-specific PCI config space access.
 */
int raw_pci_read(unsigned int domain, unsigned int bus,
		  unsigned int devfn, int reg, int len, u32 *val)
{
	struct pci_bus *b = pci_find_bus(domain, bus);

	if (!b)
		return PCIBIOS_DEVICE_NOT_FOUND;
	return b->ops->read(b, devfn, reg, len, val);
}

int raw_pci_write(unsigned int domain, unsigned int bus,
		unsigned int devfn, int reg, int len, u32 val)
{
	struct pci_bus *b = pci_find_bus(domain, bus);

	if (!b)
		return PCIBIOS_DEVICE_NOT_FOUND;
	return b->ops->write(b, devfn, reg, len, val);
}


struct acpi_pci_generic_root_info {
	struct acpi_pci_root_info	common;
	struct pci_config_window	*cfg;	/* config space mapping */
};

int acpi_pci_bus_find_domain_nr(struct pci_bus *bus)
{
	struct pci_config_window *cfg = bus->sysdata;
	struct acpi_device *adev = to_acpi_device(cfg->parent);
	struct acpi_pci_root *root = acpi_driver_data(adev);

	return root->segment;
}

static int pci_acpi_root_prepare_resources(struct acpi_pci_root_info *ci)
{
	struct resource_entry *entry, *tmp;
	int status;

	status = acpi_pci_probe_root_resources(ci);
	resource_list_for_each_entry_safe(entry, tmp, &ci->resources) {
		if (!(entry->res->flags & IORESOURCE_WINDOW))
			resource_list_destroy_entry(entry);
	}
	return status;
}

/*
 * Lookup the bus range for the domain in MCFG, and set up config space
 * mapping.
 */
static struct pci_config_window *
pci_acpi_setup_ecam_mapping(struct acpi_pci_root *root)
{
	struct device *dev = &root->device->dev;
	struct resource *bus_res = &root->secondary;
	u16 seg = root->segment;
	const struct pci_ecam_ops *ecam_ops;
	struct resource cfgres;
	struct acpi_device *adev;
	struct pci_config_window *cfg;
	int ret;

	ret = pci_mcfg_lookup(root, &cfgres, &ecam_ops);
	if (ret) {
		dev_err(dev, "%04x:%pR ECAM region not found\n", seg, bus_res);
		return NULL;
	}

	adev = acpi_resource_consumer(&cfgres);
	if (adev)
		dev_info(dev, "ECAM area %pR reserved by %s\n", &cfgres,
			 dev_name(&adev->dev));
	else
		dev_warn(dev, FW_BUG "ECAM area %pR not reserved in ACPI namespace\n",
			 &cfgres);

	cfg = pci_ecam_create(dev, &cfgres, bus_res, ecam_ops);
	if (IS_ERR(cfg)) {
		dev_err(dev, "%04x:%pR error %ld mapping ECAM\n", seg, bus_res,
			PTR_ERR(cfg));
		return NULL;
	}

	return cfg;
}

/* release_info: free resources allocated by init_info */
static void pci_acpi_generic_release_info(struct acpi_pci_root_info *ci)
{
	struct acpi_pci_generic_root_info *ri;

	ri = container_of(ci, struct acpi_pci_generic_root_info, common);
	pci_ecam_free(ri->cfg);
	kfree(ci->ops);
	kfree(ri);
}


/* Interface called from ACPI code to setup PCI host controller */
struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
{
	struct acpi_pci_generic_root_info *ri;
	struct pci_bus *bus, *child;
	struct acpi_pci_root_ops *root_ops;
	struct pci_host_bridge *host;

	ri = kzalloc(sizeof(*ri), GFP_KERNEL);
	if (!ri)
		return NULL;

	root_ops = kzalloc(sizeof(*root_ops), GFP_KERNEL);
	if (!root_ops) {
		kfree(ri);
		return NULL;
	}

	ri->cfg = pci_acpi_setup_ecam_mapping(root);
	if (!ri->cfg) {
		kfree(ri);
		kfree(root_ops);
		return NULL;
	}

	root_ops->release_info = pci_acpi_generic_release_info;
	root_ops->prepare_resources = pci_acpi_root_prepare_resources;
	root_ops->pci_ops = (struct pci_ops *)&ri->cfg->ops->pci_ops;
	bus = acpi_pci_root_create(root, root_ops, &ri->common, ri->cfg);
	if (!bus)
		return NULL;

	/* If we must preserve the resource configuration, claim now */
	host = pci_find_host_bridge(bus);
	if (host->preserve_config)
		pci_bus_claim_resources(bus);

	/*
	 * Assign whatever was left unassigned. If we didn't claim above,
	 * this will reassign everything.
	 */
	pci_assign_unassigned_root_bus_resources(bus);

	list_for_each_entry(child, &bus->children, node)
		pcie_bus_configure_settings(child);

	return bus;
}

#endif	/* CONFIG_PCI */
