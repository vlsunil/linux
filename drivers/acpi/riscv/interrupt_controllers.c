
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/fwnode.h>
#include <linux/irqchip/riscv-aplic.h>
#include <linux/list.h>
#include <linux/msi.h>
#include <linux/property.h>
#include <linux/platform_device.h>

struct list_head rintc_swnode_list;
struct rintc_swnode_list {
	struct fwnode_handle *fwnode;
	struct list_head list;
};

LIST_HEAD(rintc_swnode_list);

/*
 * the ext_intc_id format is as follows:
 * Bits [31:24] APLIC/PLIC ID
 * Bits [15:0] APLIC IDC ID / PLIC S-Mode Context ID for this hart
 */
#define APLIC_PLIC_ID(x) (x >> 24)
#define IDC_CONTEXT_ID(x) (x & 0x0000ffff)

struct fwnode_handle *acpi_rintc_create_swnode(struct acpi_madt_rintc *rintc)
{
	struct property_entry props[6] = {};
	struct fwnode_handle *fwnode;
	struct rintc_swnode_list *rintc_element;

	props[0] = PROPERTY_ENTRY_U8("version", rintc->version);
	props[1] = PROPERTY_ENTRY_U64("hartid", rintc->hart_id);
	props[2] = PROPERTY_ENTRY_U32("acpi_uid", rintc->uid);
	props[3] = PROPERTY_ENTRY_U32("ext_intc_id", rintc->ext_intc_id);
	props[4] = PROPERTY_ENTRY_U64("imsic_addr", rintc->imsic_addr);
	props[5] = PROPERTY_ENTRY_U32("imsic_size", rintc->imsic_size);

	fwnode = fwnode_create_software_node(props, NULL);
	if (fwnode) {
		rintc_element = kzalloc(sizeof(*rintc_element), GFP_KERNEL);
		if (!rintc_element)
			return NULL;

		rintc_element->fwnode = fwnode;
		list_add_tail(&rintc_element->list, &rintc_swnode_list);
	}

	return fwnode ? fwnode : NULL;
}

static struct fwnode_handle *acpi_imsic_get_matching_rintc_fwnode(u32 idx)
{
	struct rintc_swnode_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	unsigned int j = 0;

	list_for_each_safe(i, tmp, &rintc_swnode_list) {
		rintc_element = list_entry(i, struct rintc_swnode_list, list);
		fwnode = rintc_element->fwnode;

		if (j == idx)
			return fwnode;

		j++;
	}

	return NULL;
}

static struct fwnode_handle *acpi_ext_intc_get_matching_rintc_fwnode(u8 in_plic_aplic_idx,
							      u16 in_idc_context_idx)
{
	struct rintc_swnode_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 id;
	u16 idc_context_id;
	int rc;

	list_for_each_safe(i, tmp, &rintc_swnode_list) {
		rintc_element = list_entry(i, struct rintc_swnode_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "ext_intc_id", &id, 1);
		if (rc)
			continue;

		id = APLIC_PLIC_ID(id);
		idc_context_id = IDC_CONTEXT_ID(id);

		if ((id == in_plic_aplic_idx) && (idc_context_id == in_idc_context_idx))
			return fwnode;
	}

	return NULL;
}

struct fwnode_handle *acpi_imsic_create_swnode(struct acpi_madt_imsic *imsic)
{
	struct property_entry props[7] = {};
	struct software_node_ref_args *refs;
	struct fwnode_handle *fwnode, *parent_fwnode;
	unsigned int nr_rintc, i;

	props[0] = PROPERTY_ENTRY_U8("riscv,guest-index-bits", imsic->guest_index_bits);
	props[1] = PROPERTY_ENTRY_U8("riscv,hart-index-bits", imsic->hart_index_bits);
	props[2] = PROPERTY_ENTRY_U8("riscv,group-index-bits", imsic->group_index_bits);
	props[3] = PROPERTY_ENTRY_U8("riscv,group-index-shift", imsic->group_index_shift);
	props[4] = PROPERTY_ENTRY_U16("riscv,num-ids", imsic->num_ids);
	props[5] = PROPERTY_ENTRY_U16("riscv,num-guest-ids", imsic->num_guest_ids);

	nr_rintc = list_count_nodes(&rintc_swnode_list);
pr_info("acpi_imsic_create_swnode: nr_rintc = %d\n", nr_rintc);
	refs = kzalloc(sizeof(*refs) * nr_rintc, GFP_KERNEL);
	for (i = 0; i < nr_rintc; i++) {
		parent_fwnode = acpi_imsic_get_matching_rintc_fwnode(i);
		refs[i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode));
	}
	props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, nr_rintc);

	fwnode = fwnode_create_software_node(props, NULL);

	return fwnode ? fwnode : NULL;
}

struct fwnode_handle *acpi_aplic_create_swnode(struct acpi_madt_aplic *aplic)
{
	struct property_entry props[4];
	struct fwnode_handle *fwnode, *parent_fwnode;
	struct software_node_ref_args *refs;
	unsigned int i;

	props[0] = PROPERTY_ENTRY_U32("riscv,gsi-base", aplic->gsi_base);
	props[1] = PROPERTY_ENTRY_U32("riscv,num-sources", aplic->num_sources);
	props[2] = PROPERTY_ENTRY_U32("riscv,num-idcs", aplic->num_idcs);
	props[3] = PROPERTY_ENTRY_U8("riscv,aplic-id", aplic->id);
	if (aplic->num_idcs) {
		refs = kzalloc(sizeof(*refs) * aplic->num_idcs, GFP_KERNEL);
		for (i = 0; i < aplic->num_idcs; i++) {
			parent_fwnode = acpi_ext_intc_get_matching_rintc_fwnode(aplic->id, i);
			refs[i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode));
		}
		props[4] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, aplic->num_idcs);
	} else {
		props[4] = PROPERTY_ENTRY_BOOL("msi-parent");

	}

	fwnode = fwnode_create_software_node(props, NULL);

	return fwnode ? fwnode : NULL;
}

int __init aplic_parse_madt(union acpi_subtable_headers *header,
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

	res->start = aplic_entry->addr;
	res->end = aplic_entry->addr +
				aplic_entry->size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	fwnode = acpi_aplic_create_swnode(aplic_entry);
	if (!fwnode)
		goto dev_put;

	plat_data.nr_idcs = aplic_entry->num_idcs;
	plat_data.gsi_base = aplic_entry->gsi_base;
	plat_data.nr_irqs = aplic_entry->num_sources;
	plat_data.aplic_id = aplic_entry->id;
	ret = platform_device_add_data(pdev, &plat_data, sizeof(plat_data));

	if (ret)
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

void riscv_acpi_aplic_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0);
}

