// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Ventana Micro Systems Inc.
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/smp.h>

struct rpmi_sysmsi_get_attrs_rx {
	s32 status;
	u32 sys_num_msi;
	u32 p2a_db_index;
	u32 flag0;
	u32 flag1;
};

#define RPMI_SYSMSI_MSI_ATTRIBUTES_FLAG0_PREF_PRIV	BIT(0)

struct rpmi_sysmsi_set_msi_state_tx {
	u32 sys_msi_index;
	u32 sys_msi_state;
};

struct rpmi_sysmsi_set_msi_state_rx {
	s32 status;
};

#define RPMI_SYSMSI_MSI_STATE_ENABLE			BIT(0)
#define RPMI_SYSMSI_MSI_STATE_PENDING			BIT(1)

struct rpmi_sysmsi_set_msi_target_tx {
	u32 sys_msi_index;
	u32 sys_msi_address_low;
	u32 sys_msi_address_high;
	u32 sys_msi_data;
};

struct rpmi_sysmsi_set_msi_target_rx {
	s32 status;
};

struct rpmi_sysmsi_priv {
	struct device *dev;
	struct mbox_client client;
	struct mbox_chan *chan;
	u32 nr_irqs;
	u32 gsi_base;
};

static int rpmi_sysmsi_get_num_msi(struct rpmi_sysmsi_priv *priv)
{
	struct rpmi_sysmsi_get_attrs_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_SYSMSI_SRV_GET_ATTRIBUTES,
					  NULL, 0, &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(priv->chan, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return rx.sys_num_msi;
}

static int rpmi_sysmsi_set_msi_state(struct rpmi_sysmsi_priv *priv,
				     u32 sys_msi_index, u32 sys_msi_state)
{
	struct rpmi_sysmsi_set_msi_state_tx tx;
	struct rpmi_sysmsi_set_msi_state_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	tx.sys_msi_index = sys_msi_index;
	tx.sys_msi_state = sys_msi_state;
	rpmi_mbox_init_send_with_response(&msg, RPMI_SYSMSI_SRV_SET_MSI_STATE,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(priv->chan, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return 0;
}

#define rpmi_sysmsi_mask(__priv, __msi_index)		\
	rpmi_sysmsi_set_msi_state(__priv, __msi_index, 0)
#define rpmi_sysmsi_unmask(__priv, __msi_index)		\
	rpmi_sysmsi_set_msi_state(__priv, __msi_index, RPMI_SYSMSI_MSI_STATE_ENABLE)

static int rpmi_sysmsi_set_msi_target(struct rpmi_sysmsi_priv *priv,
				      u32 sys_msi_index, struct msi_msg *m)
{
	struct rpmi_sysmsi_set_msi_target_tx tx;
	struct rpmi_sysmsi_set_msi_target_rx rx;
	struct rpmi_mbox_message msg;
	int ret;

	tx.sys_msi_index = sys_msi_index;
	tx.sys_msi_address_low = m->address_lo;
	tx.sys_msi_address_high = m->address_hi;
	tx.sys_msi_data = m->data;
	rpmi_mbox_init_send_with_response(&msg, RPMI_SYSMSI_SRV_SET_MSI_TARGET,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = rpmi_mbox_send_message(priv->chan, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(rx.status);

	return 0;
}

static void rpmi_sysmsi_irq_mask(struct irq_data *d)
{
	struct rpmi_sysmsi_priv *priv = irq_data_get_irq_chip_data(d);
	int ret;

	ret = rpmi_sysmsi_mask(priv, d->hwirq);
	if (ret)
		dev_warn(priv->dev, "Failed to mask hwirq %d (error %d)\n",
			 (u32)d->hwirq, ret);
	irq_chip_mask_parent(d);
}

static void rpmi_sysmsi_irq_unmask(struct irq_data *d)
{
	struct rpmi_sysmsi_priv *priv = irq_data_get_irq_chip_data(d);
	int ret;

	irq_chip_unmask_parent(d);
	ret = rpmi_sysmsi_unmask(priv, d->hwirq);
	if (ret)
		dev_warn(priv->dev, "Failed to unmask hwirq %d (error %d)\n",
			 (u32)d->hwirq, ret);
}

static void rpmi_sysmsi_write_msg(struct irq_data *d, struct msi_msg *msg)
{
	struct rpmi_sysmsi_priv *priv = irq_data_get_irq_chip_data(d);
	int ret;

	/* For zeroed MSI, do nothing as of now */
	if (!msg->address_hi && !msg->address_lo && !msg->data)
		return;

	ret = rpmi_sysmsi_set_msi_target(priv, d->hwirq, msg);
	if (ret)
		dev_warn(priv->dev, "Failed to set target for hwirq %d (error %d)\n",
			 (u32)d->hwirq, ret);
}

static void rpmi_sysmsi_set_desc(msi_alloc_info_t *arg, struct msi_desc *desc)
{
	arg->desc = desc;
	arg->hwirq = (u32)desc->data.icookie.value;
}

static int rpmi_sysmsi_translate(struct irq_domain *d, struct irq_fwspec *fwspec,
				 unsigned long *hwirq, unsigned int *type)
{
	struct msi_domain_info *info = d->host_data;
	struct rpmi_sysmsi_priv *priv = info->data;

	if (WARN_ON(fwspec->param_count < 1))
		return -EINVAL;

	/* For DT, gsi_base is always zero. */
	*hwirq = fwspec->param[0] - priv->gsi_base;
	*type = IRQ_TYPE_NONE;
	return 0;
}

static const struct msi_domain_template rpmi_sysmsi_template = {
	.chip = {
		.name			= "RPMI-SYSMSI",
		.irq_mask		= rpmi_sysmsi_irq_mask,
		.irq_unmask		= rpmi_sysmsi_irq_unmask,
#ifdef CONFIG_SMP
		.irq_set_affinity	= irq_chip_set_affinity_parent,
#endif
		.irq_write_msi_msg	= rpmi_sysmsi_write_msg,
		.flags			= IRQCHIP_SET_TYPE_MASKED |
					  IRQCHIP_SKIP_SET_WAKE |
					  IRQCHIP_MASK_ON_SUSPEND,
	},

	.ops = {
		.set_desc		= rpmi_sysmsi_set_desc,
		.msi_translate		= rpmi_sysmsi_translate,
	},

	.info = {
		.bus_token		= DOMAIN_BUS_WIRED_TO_MSI,
		.flags			= MSI_FLAG_USE_DEV_FWNODE,
		.handler		= handle_simple_irq,
		.handler_name		= "simple",
	},
};

static int rpmi_sysmsi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rpmi_sysmsi_priv *priv;
	int rc;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->dev = dev;
	platform_set_drvdata(pdev, priv);

	/* Setup mailbox client */
	priv->client.dev		= priv->dev;
	priv->client.rx_callback	= NULL;
	priv->client.tx_block		= false;
	priv->client.knows_txdone	= true;
	priv->client.tx_tout		= 0;

	/* Request mailbox channel */
	priv->chan = mbox_request_channel(&priv->client, 0);
	if (IS_ERR(priv->chan))
		return PTR_ERR(priv->chan);

	/* Get number of system MSIs */
	rc = rpmi_sysmsi_get_num_msi(priv);
	if (rc < 1) {
		mbox_free_channel(priv->chan);
		return dev_err_probe(dev, -ENODEV, "No system MSIs found\n");
	}
	priv->nr_irqs = rc;

	/* Set the device MSI domain if not available */
	if (!dev_get_msi_domain(dev)) {
		/*
		 * The device MSI domain for OF devices is only set at the
		 * time of populating/creating OF device. If the device MSI
		 * domain is discovered later after the OF device is created
		 * then we need to set it explicitly before using any platform
		 * MSI functions.
		 */
		if (is_of_node(dev->fwnode))
			of_msi_configure(dev, to_of_node(dev->fwnode));

		if (!dev_get_msi_domain(dev))
			return -EPROBE_DEFER;
	}

	if (!msi_create_device_irq_domain(dev, MSI_DEFAULT_DOMAIN,
					  &rpmi_sysmsi_template,
					  priv->nr_irqs, priv, priv))
		return dev_err_probe(dev, -ENOMEM, "failed to create MSI irq domain\n");

	dev_info(dev, "%d system MSIs registered\n", priv->nr_irqs);
	return 0;
}

static const struct of_device_id rpmi_sysmsi_match[] = {
	{ .compatible = "riscv,rpmi-system-msi" },
	{}
};

static struct platform_driver rpmi_sysmsi_driver = {
	.driver = {
		.name		= "rpmi-sysmsi",
		.of_match_table	= rpmi_sysmsi_match,
	},
	.probe = rpmi_sysmsi_probe,
};
builtin_platform_driver(rpmi_sysmsi_driver);
