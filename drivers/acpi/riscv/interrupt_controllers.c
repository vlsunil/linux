
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


struct riscv_acpi_irqchip_fwid {
	char				*name;
	struct fwnode_handle		fwnode;
	const struct property_entry	*properties;
};

struct riscv_swnode_list {
	struct fwnode_handle *fwnode;
	struct list_head list;
};

LIST_HEAD(rintc_list);
LIST_HEAD(aplic_list);

/**
 * struct riscv_acpi_irqchip_fwid_ref_args - Reference property with additional arguments
 * @node: Reference to a software node
 * @nargs: Number of elements in @args array
 * @args: Integer arguments
 */
struct riscv_acpi_irqchip_fwid_ref_args {
        struct riscv_acpi_irqchip_fwid *node;
        unsigned int nargs;
        u64 args[NR_FWNODE_REFERENCE_ARGS];
};

#define RISCV_ACPI_FWID_REFERENCE(_ref_, ...)                     \
(const struct riscv_acpi_irqchip_fwid_ref_args) {                         \
        .node = _ref_,                                          \
        .nargs = ARRAY_SIZE(((u64[]){ 0, ##__VA_ARGS__ })) - 1, \
        .args = { __VA_ARGS__ },                                \
}

/* -------------------------------------------------------------------------- */
/* property_entry processing */

static const struct property_entry *
property_entry_get(const struct property_entry *prop, const char *name)
{
	if (!prop)
		return NULL;

	for (; prop->name; prop++)
		if (!strcmp(name, prop->name))
			return prop;

	return NULL;
}

static const void *property_get_pointer(const struct property_entry *prop)
{
	if (!prop->length)
		return NULL;

	return prop->is_inline ? &prop->value : prop->pointer;
}

static const void *property_entry_find(const struct property_entry *props,
				       const char *propname, size_t length)
{
	const struct property_entry *prop;
	const void *pointer;

	prop = property_entry_get(props, propname);
	if (!prop)
		return ERR_PTR(-EINVAL);
	pointer = property_get_pointer(prop);
	if (!pointer)
		return ERR_PTR(-ENODATA);
	if (length > prop->length)
		return ERR_PTR(-EOVERFLOW);
	return pointer;
}

static int
property_entry_count_elems_of_size(const struct property_entry *props,
				   const char *propname, size_t length)
{
	const struct property_entry *prop;

	prop = property_entry_get(props, propname);
	if (!prop)
		return -EINVAL;

	return prop->length / length;
}

static int property_entry_read_int_array(const struct property_entry *props,
					 const char *name,
					 unsigned int elem_size, void *val,
					 size_t nval)
{
	const void *pointer;
	size_t length;

	if (!val)
		return property_entry_count_elems_of_size(props, name,
							  elem_size);

	if (!is_power_of_2(elem_size) || elem_size > sizeof(u64))
		return -ENXIO;

	length = nval * elem_size;

	pointer = property_entry_find(props, name, length);
	if (IS_ERR(pointer))
		return PTR_ERR(pointer);

	memcpy(val, pointer, length);
	return 0;
}

static bool riscv_acpi_irqchip_fwnode_property_present(const struct fwnode_handle *fwnode,
					   const char *propname)
{
	struct riscv_acpi_irqchip_fwid *fwid = container_of(fwnode, struct riscv_acpi_irqchip_fwid, fwnode);

	return !!property_entry_get(fwid->properties, propname);
}

static int riscv_acpi_irqchip_fwnode_read_int_array(const struct fwnode_handle *fwnode,
					const char *propname,
					unsigned int elem_size, void *val,
					size_t nval)
{
	struct riscv_acpi_irqchip_fwid *fwid = container_of(fwnode, struct riscv_acpi_irqchip_fwid, fwnode);

	return property_entry_read_int_array(fwid->properties, propname,
					     elem_size, val, nval);
}

static const char *riscv_acpi_irqchip_fwnode_get_name(const struct fwnode_handle *fwnode)
{
	struct riscv_acpi_irqchip_fwid *fwid = container_of(fwnode, struct riscv_acpi_irqchip_fwid, fwnode);

	return fwid->name;
}

static int
riscv_acpi_irqchip_fwnode_get_reference_args(const struct fwnode_handle *fwnode,
				 const char *propname, const char *nargs_prop,
				 unsigned int nargs, unsigned int index,
				 struct fwnode_reference_args *args)
{
	struct riscv_acpi_irqchip_fwid *fwid = container_of(fwnode, struct riscv_acpi_irqchip_fwid, fwnode);
	const struct riscv_acpi_irqchip_fwid_ref_args *ref_array;
	const struct riscv_acpi_irqchip_fwid_ref_args *ref;
	const struct property_entry *prop;
	struct fwnode_handle *refnode;
	u32 nargs_prop_val;
	int error;
	int i;

	prop = property_entry_get(fwid->properties, propname);
	if (!prop) {
		return -ENOENT;
	}

	if (prop->type != DEV_PROP_REF)
		return -EINVAL;

	/*
	 * We expect that references are never stored inline, even
	 * single ones, as they are too big.
	 */
	if (prop->is_inline)
		return -EINVAL;

	if (index * sizeof(*ref) >= prop->length)
		return -ENOENT;

	ref_array = prop->pointer;
	ref = &ref_array[index];

	refnode = &(ref->node->fwnode);
	if (!refnode)
		return -ENOENT;

	if (nargs_prop) {
		error = property_entry_read_int_array(ref->node->properties,
						      nargs_prop, sizeof(u32),
						      &nargs_prop_val, 1);
		if (error) {
			return error;
		}

		nargs = nargs_prop_val;
	}

	if (nargs > NR_FWNODE_REFERENCE_ARGS)
		return -EINVAL;

	args->fwnode = refnode;
	args->nargs = nargs;

	for (i = 0; i < nargs; i++)
		args->args[i] = ref->args[i];

	return 0;
}

const struct fwnode_operations riscv_acpi_irqchip_fwnode_ops = {
	.property_present = riscv_acpi_irqchip_fwnode_property_present,
	.property_read_int_array = riscv_acpi_irqchip_fwnode_read_int_array,
	.get_name = riscv_acpi_irqchip_fwnode_get_name,
	.get_reference_args = riscv_acpi_irqchip_fwnode_get_reference_args,
};
EXPORT_SYMBOL_GPL(riscv_acpi_irqchip_fwnode_ops);

static inline bool is_riscv_acpi_irqchip(struct fwnode_handle *fwnode)
{
        return fwnode && fwnode->ops == &riscv_acpi_irqchip_fwnode_ops;
}

#define to_riscv_acpi_irqchip_node(__fwnode)                                   \
        ({                                                              \
                typeof(__fwnode) __to_riscv_acpi_irqchip_node_fwnode = __fwnode; \
                                                                        \
                is_riscv_acpi_irqchip(__to_riscv_acpi_irqchip_node_fwnode) ?     \
                        container_of(__to_riscv_acpi_irqchip_node_fwnode,      \
                                     struct riscv_acpi_irqchip_fwid, fwnode) :      \
                        NULL;                                           \
        })

/**
 * riscv_acpi_irqchip_create_fwnode - Allocate a fwnode_handle suitable for
 *                           identifying an irq domain for RISC-V ACPI
 * @id:		Optional user provided id if name != NULL
 * @name:	Optional user provided domain name
 *
 * Allocate a struct riscv_acpi_irqchip_fwid, and return a pointer to the embedded
 * fwnode_handle (or NULL on failure).
 *
 */
struct fwnode_handle *riscv_acpi_irqchip_create_fwnode(const struct property_entry *properties,
						       int id,
						       const char *name)
{
	struct riscv_acpi_irqchip_fwid *fwid;
	struct property_entry *props;
	char *n;

	fwid = kzalloc(sizeof(*fwid), GFP_KERNEL);

	n = kasprintf(GFP_KERNEL, "%s-%d", name, id);

	props = property_entries_dup(properties);

	if (!fwid || !n || !props) {
		kfree(fwid);
		kfree(n);
		return NULL;
	}
	
	fwid->properties = props;
	fwid->name = n;
	fwnode_init(&fwid->fwnode, &riscv_acpi_irqchip_fwnode_ops);
	return &fwid->fwnode;
}
EXPORT_SYMBOL_GPL(riscv_acpi_irqchip_create_fwnode);

static struct fwnode_handle *imsic_acpi_fwnode;
/*
 * the ext_intc_id format is as follows:
 * Bits [31:24] APLIC/PLIC ID
 * Bits [15:0] APLIC IDC ID / PLIC S-Mode Context ID for this hart
 */
#define APLIC_PLIC_ID(x) (x >> 24)
#define IDC_CONTEXT_ID(x) (x & 0x0000ffff)

static int acpi_rintc_create_swnode(struct acpi_madt_rintc *rintc)
{
	struct property_entry props[7] = {};
	struct fwnode_handle *fwnode;
	struct riscv_swnode_list *rintc_element;

	props[0] = PROPERTY_ENTRY_U32("version", rintc->version);
	props[1] = PROPERTY_ENTRY_U64("hartid", rintc->hart_id);
	props[2] = PROPERTY_ENTRY_U32("acpi_uid", rintc->uid);
	props[3] = PROPERTY_ENTRY_U32("ext_intc_id", rintc->ext_intc_id);
	props[4] = PROPERTY_ENTRY_U64("imsic_addr", rintc->imsic_addr);
	props[5] = PROPERTY_ENTRY_U32("imsic_size", rintc->imsic_size);
	props[6] = PROPERTY_ENTRY_U32("#interrupt-cells", 1);

	fwnode = riscv_acpi_irqchip_create_fwnode(props, rintc->uid, "RISC-V INTC");
	if (fwnode) {
		rintc_element = kzalloc(sizeof(*rintc_element), GFP_KERNEL);
		if (!rintc_element) {
			return -1;
		}

		rintc_element->fwnode = fwnode;
		list_add_tail(&rintc_element->list, &rintc_list);
	}

	return fwnode ? 0 : -1;
}

struct fwnode_handle *acpi_rintc_get_fwnode(u32 uid)
{
	struct riscv_swnode_list *rintc_element;
	struct list_head *i, *tmp;
	struct fwnode_handle *fwnode;
	u32 acpi_id;
	int rc;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_swnode_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "acpi_uid", &acpi_id, 1);
		if (!rc && acpi_id == uid)
			return fwnode;
	}

	return NULL;
}

static struct fwnode_handle *acpi_imsic_get_matching_rintc_fwnode(u32 idx)
{
	struct riscv_swnode_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	unsigned int j = 0;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_swnode_list, list);
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
	struct riscv_swnode_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 id;
        u8 aplic_id;
	u16 idc_context_id;
	int rc;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_swnode_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "ext_intc_id", &id, 1);
		if (rc)
			continue;
		aplic_id = APLIC_PLIC_ID(id);
		idc_context_id = IDC_CONTEXT_ID(id);

		if ((aplic_id == in_plic_aplic_idx) && (idc_context_id == in_idc_context_idx))
			return fwnode;
	}

	return NULL;
}

static int acpi_imsic_create_swnode(struct acpi_madt_imsic *imsic)
{
	struct property_entry props[7] = {};
	struct riscv_acpi_irqchip_fwid_ref_args *refs;
	struct fwnode_handle *parent_fwnode;
	unsigned int nr_rintc, i;

	props[0] = PROPERTY_ENTRY_U32("riscv,guest-index-bits", imsic->guest_index_bits);
	props[1] = PROPERTY_ENTRY_U32("riscv,hart-index-bits", imsic->hart_index_bits);
	props[2] = PROPERTY_ENTRY_U32("riscv,group-index-bits", imsic->group_index_bits);
	props[3] = PROPERTY_ENTRY_U32("riscv,group-index-shift", imsic->group_index_shift);
	props[4] = PROPERTY_ENTRY_U32("riscv,num-ids", imsic->num_ids);
	props[5] = PROPERTY_ENTRY_U32("riscv,num-guest-ids", imsic->num_guest_ids);

	nr_rintc = list_count_nodes(&rintc_list);
	refs = kzalloc(sizeof(*refs) * nr_rintc, GFP_KERNEL);
	for (i = 0; i < nr_rintc; i++) {
		parent_fwnode = acpi_imsic_get_matching_rintc_fwnode(i);
		refs[i] = RISCV_ACPI_FWID_REFERENCE(to_riscv_acpi_irqchip_node(parent_fwnode), RV_IRQ_EXT);
	}
	props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, nr_rintc);

	imsic_acpi_fwnode = riscv_acpi_irqchip_create_fwnode(props, 0, "RISC-V IMSIC");

	return imsic_acpi_fwnode ? 0 : -1;
}

struct fwnode_handle *acpi_imsic_get_fwnode(struct device *dev)
{
	return imsic_acpi_fwnode;
}

static int __init aplic_create_platform_device(union acpi_subtable_headers *header,
					       const unsigned long end)
{
	struct acpi_madt_aplic *aplic_entry = (struct acpi_madt_aplic *) header;
	struct fwnode_handle *fwnode;
	struct platform_device *pdev;
	struct irq_domain *msi_domain;
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

	fwnode = acpi_aplic_get_fwnode(aplic_entry->id);
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

static int acpi_aplic_create_swnode(struct acpi_madt_aplic *aplic)
{
	struct property_entry props[5];
	struct fwnode_handle *fwnode, *parent_fwnode;
	struct riscv_swnode_list *aplic_element;
	struct riscv_acpi_irqchip_fwid_ref_args *refs;
	unsigned int i;
	int rc = -1;

	props[0] = PROPERTY_ENTRY_U32("riscv,gsi-base", aplic->gsi_base);
	props[1] = PROPERTY_ENTRY_U32("riscv,num-sources", aplic->num_sources);
	props[2] = PROPERTY_ENTRY_U32("riscv,num-idcs", aplic->num_idcs);
	props[3] = PROPERTY_ENTRY_U32("riscv,aplic-id", aplic->id);
	if (aplic->num_idcs) {
		refs = kzalloc(sizeof(*refs) * aplic->num_idcs, GFP_KERNEL);
		for (i = 0; i < aplic->num_idcs; i++) {
			parent_fwnode = acpi_ext_intc_get_matching_rintc_fwnode(aplic->id, i);
			refs[i] = RISCV_ACPI_FWID_REFERENCE(to_riscv_acpi_irqchip_node(parent_fwnode), RV_IRQ_EXT);
		}
		props[4] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, aplic->num_idcs);
	} else {
		props[4] = PROPERTY_ENTRY_BOOL("msi-parent");

	}

	fwnode = riscv_acpi_irqchip_create_fwnode(props, aplic->id, "RISC-V APLIC");

	if (fwnode) {
		aplic_element = kzalloc(sizeof(*aplic_element), GFP_KERNEL);
		if (!aplic_element) {
			return -1;
		}

		aplic_element->fwnode = fwnode;
		list_add_tail(&aplic_element->list, &aplic_list);
	}

	return (fwnode && !rc) ? 0 : -1;
}

struct fwnode_handle *acpi_aplic_get_fwnode(u32 aplic_id)
{
	struct riscv_swnode_list *aplic_element;
	struct list_head *i, *tmp;
	struct fwnode_handle *fwnode;
	int rc;
	u32 id;

	list_for_each_safe(i, tmp, &aplic_list) {
		aplic_element = list_entry(i, struct riscv_swnode_list, list);
		fwnode = aplic_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,aplic-id", &id, 1);
		if ((!rc) && (aplic_id == id))
			return fwnode;
	}

	return NULL;
}

struct fwnode_handle *aplic_get_gsi_domain_id(u32 gsi)
{
	struct riscv_swnode_list *aplic_element;
	struct list_head *i, *tmp;
	struct fwnode_handle *fwnode;
	int rc;
	u32 gsi_base;
	u32 nr_irqs;

	list_for_each_safe(i, tmp, &aplic_list) {
		aplic_element = list_entry(i, struct riscv_swnode_list, list);
		fwnode = aplic_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,gsi-base", &gsi_base, 1);
		rc = fwnode_property_read_u32_array(fwnode, "riscv,num-sources", &nr_irqs, 1);
		if ((!rc) && (gsi >= gsi_base && gsi < gsi_base + nr_irqs))
			return fwnode;
	}

	return NULL;
}

static int __init rintc_parse_madt_swnode(union acpi_subtable_headers *header,
					  const unsigned long end)
{
	struct acpi_madt_rintc *rintc = (struct acpi_madt_rintc *)header;

	return acpi_rintc_create_swnode(rintc);
}

static int __init imsic_parse_madt_swnode(union acpi_subtable_headers *header,
					  const unsigned long end)
{
	struct acpi_madt_imsic *imsic = (struct acpi_madt_imsic *)header;

	return acpi_imsic_create_swnode(imsic);
}

static int __init aplic_parse_madt_swnode(union acpi_subtable_headers *header,
					  const unsigned long end)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;

	return acpi_aplic_create_swnode(aplic);
}

void acpi_init_fwnodes()
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_RINTC, rintc_parse_madt_swnode, 0);
	acpi_table_parse_madt(ACPI_MADT_TYPE_IMSIC, imsic_parse_madt_swnode, 0);
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt_swnode, 0);
}

bool arch_is_fwnode_irqchip(const struct fwnode_handle *fwnode)
{
	return !IS_ERR_OR_NULL(fwnode) && fwnode->ops == &riscv_acpi_irqchip_fwnode_ops;
}

int riscv_acpi_aplic_init()
{
	return acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_create_platform_device, 0);
}

