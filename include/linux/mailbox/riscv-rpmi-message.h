/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Ventana Micro Systems Inc.
 */

#ifndef _LINUX_RISCV_RPMI_MESSAGE_H_
#define _LINUX_RISCV_RPMI_MESSAGE_H_

#include <linux/mailbox_client.h>

/** RPMI version encode/decode macros */
#define RPMI_VER_MAJOR(__ver)		(((__ver) >> 16) & 0xffff)
#define RPMI_VER_MINOR(__ver)		((__ver) & 0xffff)
#define RPMI_MKVER(__maj, __min)	(((__maj) << 16) | (__min))

/** RPMI message header */
struct rpmi_message_header {
	__le16 servicegroup_id;
	u8 service_id;
	u8 flags;
	__le16 datalen;
	__le16 token;
};

/** RPMI message */
struct rpmi_message {
	struct rpmi_message_header header;
	u8 data[];
};

/** RPMI notification event */
struct rpmi_notification_event {
	__le16 event_datalen;
	u8 event_id;
	u8 reserved;
	u8 event_data[];
};

/** RPMI error codes */
enum rpmi_error_codes {
	RPMI_SUCCESS			= 0,
	RPMI_ERR_FAILED			= -1,
	RPMI_ERR_NOTSUPP		= -2,
	RPMI_ERR_INVALID_PARAM		= -3,
	RPMI_ERR_DENIED			= -4,
	RPMI_ERR_INVALID_ADDR		= -5,
	RPMI_ERR_ALREADY		= -6,
	RPMI_ERR_EXTENSION		= -7,
	RPMI_ERR_HW_FAULT		= -8,
	RPMI_ERR_BUSY			= -9,
	RPMI_ERR_INVALID_STATE		= -10,
	RPMI_ERR_BAD_RANGE		= -11,
	RPMI_ERR_TIMEOUT		= -12,
	RPMI_ERR_IO			= -13,
	RPMI_ERR_NO_DATA		= -14,
	RPMI_ERR_RESERVED_START		= -15,
	RPMI_ERR_RESERVED_END		= -127,
	RPMI_ERR_VENDOR_START		= -128,
};

static inline int rpmi_to_linux_error(int rpmi_error)
{
	switch (rpmi_error) {
	case RPMI_SUCCESS:
		return 0;
	case RPMI_ERR_INVALID_PARAM:
	case RPMI_ERR_BAD_RANGE:
	case RPMI_ERR_INVALID_STATE:
		return -EINVAL;
	case RPMI_ERR_DENIED:
		return -EPERM;
	case RPMI_ERR_INVALID_ADDR:
	case RPMI_ERR_HW_FAULT:
		return -EFAULT;
	case RPMI_ERR_ALREADY:
		return -EALREADY;
	case RPMI_ERR_BUSY:
		return -EBUSY;
	case RPMI_ERR_TIMEOUT:
		return -ETIMEDOUT;
	case RPMI_ERR_IO:
		return -ECOMM;
	case RPMI_ERR_FAILED:
	case RPMI_ERR_NOTSUPP:
	case RPMI_ERR_NO_DATA:
	case RPMI_ERR_EXTENSION:
	default:
		return -EOPNOTSUPP;
	}
}

/** RPMI service group IDs */
#define RPMI_SRVGRP_CLOCK		0x00008

/** RPMI clock service IDs */
enum rpmi_clock_service_id {
	RPMI_CLK_SRV_ENABLE_NOTIFICATION = 0x01,
	RPMI_CLK_SRV_GET_NUM_CLOCKS = 0x02,
	RPMI_CLK_SRV_GET_ATTRIBUTES = 0x03,
	RPMI_CLK_SRV_GET_SUPPORTED_RATES = 0x04,
	RPMI_CLK_SRV_SET_CONFIG = 0x05,
	RPMI_CLK_SRV_GET_CONFIG = 0x06,
	RPMI_CLK_SRV_SET_RATE = 0x07,
	RPMI_CLK_SRV_GET_RATE = 0x08,
	RPMI_CLK_SRV_ID_MAX_COUNT,
};

/** RPMI linux mailbox attribute IDs */
enum rpmi_mbox_attribute_id {
	RPMI_MBOX_ATTR_SPEC_VERSION = 0,
	RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE,
	RPMI_MBOX_ATTR_SERVICEGROUP_ID,
	RPMI_MBOX_ATTR_SERVICEGROUP_VERSION,
	RPMI_MBOX_ATTR_MAX_ID,
};

/** RPMI linux mailbox message types */
enum rpmi_mbox_message_type {
	RPMI_MBOX_MSG_TYPE_GET_ATTRIBUTE = 0,
	RPMI_MBOX_MSG_TYPE_SET_ATTRIBUTE,
	RPMI_MBOX_MSG_TYPE_SEND_WITH_RESPONSE,
	RPMI_MBOX_MSG_TYPE_SEND_WITHOUT_RESPONSE,
	RPMI_MBOX_MSG_TYPE_NOTIFICATION_EVENT,
	RPMI_MBOX_MSG_MAX_TYPE,
};

/** RPMI linux mailbox message instance */
struct rpmi_mbox_message {
	enum rpmi_mbox_message_type type;
	union {
		struct {
			enum rpmi_mbox_attribute_id id;
			u32 value;
		} attr;

		struct {
			u32 service_id;
			void *request;
			unsigned long request_len;
			void *response;
			unsigned long max_response_len;
			unsigned long out_response_len;
		} data;

		struct {
			u16 event_datalen;
			u8 event_id;
			u8 *event_data;
		} notif;
	};
	int error;
};

/** RPMI linux mailbox message helper routines */
static inline void rpmi_mbox_init_get_attribute(struct rpmi_mbox_message *msg,
						enum rpmi_mbox_attribute_id id)
{
	msg->type = RPMI_MBOX_MSG_TYPE_GET_ATTRIBUTE;
	msg->attr.id = id;
	msg->attr.value = 0;
	msg->error = 0;
}

static inline void rpmi_mbox_init_set_attribute(struct rpmi_mbox_message *msg,
						enum rpmi_mbox_attribute_id id,
						u32 value)
{
	msg->type = RPMI_MBOX_MSG_TYPE_SET_ATTRIBUTE;
	msg->attr.id = id;
	msg->attr.value = value;
	msg->error = 0;
}

static inline void rpmi_mbox_init_send_with_response(struct rpmi_mbox_message *msg,
						     u32 service_id,
						     void *request,
						     unsigned long request_len,
						     void *response,
						     unsigned long max_response_len)
{
	msg->type = RPMI_MBOX_MSG_TYPE_SEND_WITH_RESPONSE;
	msg->data.service_id = service_id;
	msg->data.request = request;
	msg->data.request_len = request_len;
	msg->data.response = response;
	msg->data.max_response_len = max_response_len;
	msg->data.out_response_len = 0;
	msg->error = 0;
}

static inline void rpmi_mbox_init_send_without_response(struct rpmi_mbox_message *msg,
							u32 service_id,
							void *request,
							unsigned long request_len)
{
	msg->type = RPMI_MBOX_MSG_TYPE_SEND_WITHOUT_RESPONSE;
	msg->data.service_id = service_id;
	msg->data.request = request;
	msg->data.request_len = request_len;
	msg->data.response = NULL;
	msg->data.max_response_len = 0;
	msg->data.out_response_len = 0;
	msg->error = 0;
}

static inline int rpmi_mbox_send_message(struct mbox_chan *chan,
					 struct rpmi_mbox_message *msg)
{
	int ret;

	/* Send message for the underlying mailbox channel */
	ret = mbox_send_message(chan, msg);
	if (ret < 0)
		return ret;

	/* Explicitly signal txdone for mailbox channel */
	ret = msg->error;
	mbox_client_txdone(chan, ret);
	return ret;
}

#endif /* _LINUX_RISCV_RPMI_MESSAGE_H_ */
