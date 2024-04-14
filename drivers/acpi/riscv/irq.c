// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/sort.h>
#include <linux/irq.h>

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

struct riscv_ext_intc_list {
	acpi_handle handle;
	u32 gsi_base;
	u32 nr_irqs;
	u32 id;
	u32 type;
	struct list_head list;
};

struct acpi_irq_dep_one_ctx {
        int rc;
        unsigned int index;
        unsigned long *res_flags;
        acpi_handle handle;
};

LIST_HEAD(ext_intc_list);

static int riscv_acpi_update_gsi_handle(u32 gsi_base, acpi_handle handle)
{
	struct riscv_ext_intc_list *ext_intc_element;
	struct list_head *i, *tmp;

pr_info("riscv_acpi_update_gsi_handle: Enter for gsi_base = %d, handle=0x%llx\n", gsi_base, handle);
	list_for_each_safe(i, tmp, &ext_intc_list) {
		ext_intc_element = list_entry(i, struct riscv_ext_intc_list, list);
		if (gsi_base == ext_intc_element->gsi_base) {
			ext_intc_element->handle = handle;
			return 0;
		}
	}

	return -1;
}

acpi_handle riscv_acpi_get_gsi_handle(u32 gsi)
{
	struct riscv_ext_intc_list *ext_intc_element;
	struct list_head *i, *tmp;

	list_for_each_safe(i, tmp, &ext_intc_list) {
		ext_intc_element = list_entry(i, struct riscv_ext_intc_list, list);
		if (gsi >= ext_intc_element->gsi_base &&
		    gsi < (ext_intc_element->gsi_base + ext_intc_element->nr_irqs))
			return ext_intc_element->handle;
	}

	return NULL;
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

static int riscv_acpi_register_ext_intc(u32 gsi_base, u32 nr_irqs,
				 u32 id, u32 type)
{
	struct riscv_ext_intc_list *ext_intc_element;

pr_info("riscv_acpi_register_ext_intc: ENter: gsi_base = %d, nr_irqs=%d, id=%d, type=%d\n", gsi_base, nr_irqs, id, type);
	ext_intc_element = kzalloc(sizeof(*ext_intc_element), GFP_KERNEL);
	if (!ext_intc_element)
		return -1;

	ext_intc_element->gsi_base = gsi_base;
	ext_intc_element->nr_irqs = nr_irqs;
	ext_intc_element->id = id;
	list_add_tail(&ext_intc_element->list, &ext_intc_list);
	return 0;
}

static acpi_status __init riscv_acpi_create_gsi_map(acpi_handle handle, u32 level,
						    void *context, void **return_value)
{
	acpi_status status;
	u64 gbase;
	int rc;

	if (!acpi_has_method(handle, "_GSB"))
		return -1;

	status = acpi_evaluate_integer(handle, "_GSB", NULL, &gbase);
	if (ACPI_FAILURE(status)) {
		acpi_handle_err(handle, "failed to evaluate _GSB method\n");
			return -1;
	}

	rc = riscv_acpi_update_gsi_handle((u32)gbase, handle);
	return rc;
}

static int __init aplic_parse_madt(union acpi_subtable_headers *header,
				   const unsigned long end)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;

	riscv_acpi_register_ext_intc(aplic->gsi_base, aplic->num_sources, aplic->id, ACPI_RISCV_IRQCHIP_APLIC);
	return 0;
}

static int __init plic_parse_madt(union acpi_subtable_headers *header,
				  const unsigned long end)
{
	struct acpi_madt_plic *plic = (struct acpi_madt_plic *)header;

	riscv_acpi_register_ext_intc(plic->gsi_base, plic->num_irqs, plic->id, ACPI_RISCV_IRQCHIP_PLIC);
	return 0;
}

int riscv_acpi_init_gsi_mapping(void)
{
	acpi_status status;
	int count = 0;

	count = acpi_table_parse_madt(ACPI_MADT_TYPE_PLIC, plic_parse_madt, 0);
	if (count <= 0)
		acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0);

	status = acpi_get_devices("RSCV0001", riscv_acpi_create_gsi_map, NULL, NULL);
	if (ACPI_FAILURE(status)) {
		status = acpi_get_devices("RSCV0002", riscv_acpi_create_gsi_map, NULL, NULL);
		if (ACPI_FAILURE(status))
			return -1;
	}

	return 0;
}

static acpi_status acpi_irq_get_parent(struct acpi_resource *ares,
					 void *context)
{
	struct acpi_irq_dep_one_ctx *ctx = context;
	struct acpi_resource_irq *irq;
	struct acpi_resource_extended_irq *eirq;

	switch (ares->type) {
	case ACPI_RESOURCE_TYPE_IRQ:
		irq = &ares->data.irq;
		if (ctx->index >= irq->interrupt_count) {
			ctx->index -= irq->interrupt_count;
			return AE_OK;
		}
		ctx->handle = riscv_acpi_get_gsi_handle(irq->interrupts[ctx->index]);
		return AE_CTRL_TERMINATE;
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
		eirq = &ares->data.extended_irq;
pr_info("acpi_irq_get_parent: hwirq = %d\n", eirq->interrupts[ctx->index]);
		if (eirq->producer_consumer == ACPI_PRODUCER)
			return AE_OK;
		if (ctx->index >= eirq->interrupt_count) {
			ctx->index -= eirq->interrupt_count;
			return AE_OK;
		}

		/* Don't support */
		if (eirq->resource_source.string_length)
			return AE_OK;

		ctx->handle = riscv_acpi_get_gsi_handle(eirq->interrupts[ctx->index]);
		return AE_CTRL_TERMINATE;
	}

	return AE_OK;
}

int acpi_irq_get_dep(acpi_handle handle, unsigned int index, acpi_handle *gsi_handle)
{
	struct acpi_irq_dep_one_ctx ctx;

pr_info("acpi_irq_get_dep: ENTER\n");
	ctx.rc = -EINVAL;
	ctx.index = index;
	acpi_walk_resources(handle, METHOD_NAME__CRS, acpi_irq_get_parent, &ctx);
	*gsi_handle = ctx.handle;
	if (*gsi_handle) {
		pr_info("acpi_irq_get_dep: Found dependency : 0x%llx\n", ctx.handle);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(acpi_irq_get_dep);
