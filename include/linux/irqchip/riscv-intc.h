/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */
#ifndef __LINUX_IRQCHIP_RISCV_INTC_H
#define __LINUX_IRQCHIP_RISCV_INTC_H

unsigned long get_riscv_timebase_freq(void);
int riscv_intc_acpi_init(void);
extern struct irq_domain *intc_domain;
extern struct fwnode_handle *intc_fwnode;

#endif
