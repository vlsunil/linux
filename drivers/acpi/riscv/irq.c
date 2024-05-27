// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2024, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/sort.h>
#include <linux/irq.h>

#include "init.h"

struct riscv_ext_intc_list {
	acpi_handle handle;
	u32 gsi_base;
	u32 nr_irqs;
	u32 nr_idcs;
	u32 id;
	u32 type;
	struct list_head list;
};

LIST_HEAD(ext_intc_list);

static int irqchip_cmp_func(const void *in0, const void *in1)
{
	struct acpi_probe_entry *elem0 = (struct acpi_probe_entry *)in0;
	struct acpi_probe_entry *elem1 = (struct acpi_probe_entry *)in1;

	return (elem0->type > elem1->type) - (elem0->type < elem1->type);
}

/*
 * RISC-V irqchips in MADT of ACPI spec are defined in the same order how
 * they should be probed. Since IRQCHIP_ACPI_DECLARE doesn't define any
 * order, this arch function will reorder the probe functions as per the
 * required order for the architecture.
 */
void arch_sort_irqchip_probe(struct acpi_probe_entry *ap_head, int nr)
{
	struct acpi_probe_entry *ape = ap_head;

	if (nr == 1 || !ACPI_COMPARE_NAMESEG(ACPI_SIG_MADT, ape->id))
		return;
	sort(ape, nr, sizeof(*ape), irqchip_cmp_func, NULL);
}

static void riscv_acpi_update_gsi_handle(u32 gsi_base, acpi_handle handle)
{
	struct riscv_ext_intc_list *ext_intc_element;
	struct list_head *i, *tmp;

	list_for_each_safe(i, tmp, &ext_intc_list) {
		ext_intc_element = list_entry(i, struct riscv_ext_intc_list, list);
		if (gsi_base == ext_intc_element->gsi_base) {
			ext_intc_element->handle = handle;
			return;
		}
	}

	acpi_handle_err(handle, "failed to find the GSI mapping entry\n");
}

int riscv_acpi_get_gsi_info(struct fwnode_handle *fwnode, u32 *gsi_base,
			    u32 *id, u32 *nr_irqs, u32 *nr_idcs)
{
	struct riscv_ext_intc_list *ext_intc_element;
	struct list_head *i, *tmp;

	list_for_each_safe(i, tmp, &ext_intc_list) {
		ext_intc_element = list_entry(i, struct riscv_ext_intc_list, list);
		if (ext_intc_element->handle == ACPI_HANDLE_FWNODE(fwnode)) {
			*gsi_base = ext_intc_element->gsi_base;
			*id = ext_intc_element->id;
			*nr_irqs = ext_intc_element->nr_irqs;
			if (nr_idcs)
				*nr_idcs = ext_intc_element->nr_idcs;

			return 0;
		}
	}

	return -ENODEV;
}

struct fwnode_handle *riscv_acpi_get_gsi_domain_id(u32 gsi)
{
	struct riscv_ext_intc_list *ext_intc_element;
	struct acpi_device *adev;
	struct list_head *i, *tmp;

	list_for_each_safe(i, tmp, &ext_intc_list) {
		ext_intc_element = list_entry(i, struct riscv_ext_intc_list, list);
		if (gsi >= ext_intc_element->gsi_base &&
		    gsi < (ext_intc_element->gsi_base + ext_intc_element->nr_irqs)) {
			adev = acpi_fetch_acpi_dev(ext_intc_element->handle);
			if (!adev)
				return NULL;

			return acpi_fwnode_handle(adev);
		}
	}

	return NULL;
}

static int __init riscv_acpi_register_ext_intc(u32 gsi_base, u32 nr_irqs, u32 nr_idcs,
					       u32 id, u32 type)
{
	struct riscv_ext_intc_list *ext_intc_element;

	ext_intc_element = kzalloc(sizeof(*ext_intc_element), GFP_KERNEL);
	if (!ext_intc_element)
		return -ENOMEM;

	ext_intc_element->gsi_base = gsi_base;
	ext_intc_element->nr_irqs = nr_irqs;
	ext_intc_element->nr_idcs = nr_idcs;
	ext_intc_element->id = id;
	list_add_tail(&ext_intc_element->list, &ext_intc_list);
	return 0;
}

static acpi_status __init riscv_acpi_create_gsi_map(acpi_handle handle, u32 level,
						    void *context, void **return_value)
{
	acpi_status status;
	u64 gbase;

	if (!acpi_has_method(handle, "_GSB")) {
		acpi_handle_err(handle, "_GSB method not found\n");
		return AE_OK;
	}

	status = acpi_evaluate_integer(handle, "_GSB", NULL, &gbase);
	if (ACPI_FAILURE(status)) {
		acpi_handle_err(handle, "failed to evaluate _GSB method\n");
		return AE_OK;
	}

	riscv_acpi_update_gsi_handle((u32)gbase, handle);
	return AE_OK;
}

static int __init riscv_acpi_aplic_parse_madt(union acpi_subtable_headers *header,
					      const unsigned long end)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;

	return riscv_acpi_register_ext_intc(aplic->gsi_base, aplic->num_sources, aplic->num_idcs,
					    aplic->id, ACPI_RISCV_IRQCHIP_APLIC);
}

static int __init riscv_acpi_plic_parse_madt(union acpi_subtable_headers *header,
					     const unsigned long end)
{
	struct acpi_madt_plic *plic = (struct acpi_madt_plic *)header;

	return riscv_acpi_register_ext_intc(plic->gsi_base, plic->num_irqs, 0,
					    plic->id, ACPI_RISCV_IRQCHIP_PLIC);
}

void __init riscv_acpi_init_gsi_mapping(void)
{
	/* There can be either PLIC or APLIC */
	if (acpi_table_parse_madt(ACPI_MADT_TYPE_PLIC, riscv_acpi_plic_parse_madt, 0) > 0) {
		acpi_get_devices("RSCV0001", riscv_acpi_create_gsi_map, NULL, NULL);
		return;
	}

	if (acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, riscv_acpi_aplic_parse_madt, 0) > 0)
		acpi_get_devices("RSCV0002", riscv_acpi_create_gsi_map, NULL, NULL);
}
