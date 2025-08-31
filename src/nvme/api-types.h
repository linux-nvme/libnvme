// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Types used as part of the libnvme/libnvme-mi API, rather than specified
 * by the NVM Express specification.
 *
 * These are shared across both libnvme and libnvme-mi interfaces.
 *
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */
#ifndef _LIBNVME_API_TYPES_H
#define _LIBNVME_API_TYPES_H

#include <stdio.h>
#include <stdbool.h>

#include <nvme/types.h>

struct nvme_root;
typedef struct nvme_root *nvme_root_t;
struct nvme_link;
typedef struct nvme_link *nvme_link_t;

/**
 * nvme_create_root() - Initialize root object
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use
 *
 * Return: Initialized &nvme_root_t object
 */
nvme_root_t nvme_create_root(FILE *fp, int log_level);

/**
 * nvme_free_root() - Free root object
 * @r:	&nvme_root_t object
 *
 * Free an &nvme_root_t object and all attached objects
 */
void nvme_free_root(nvme_root_t r);

/*
 * _args struct definitions. These are used by both the ioctl-based and
 * MI-based interfaces, as the call interface for (admin/io/etc) NVMe commands,
 * passed to the nvme_*() and nvme_mi_*() functions.
 *
 * On MI-based interfaces, the fd and timeout members are unused, and should
 * be set to zero.
 */

/**
 * struct nvme_get_features_args - Arguments for the NVMe Admin Get Feature command
 * @args_size:	Size of &struct nvme_get_features_args
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @cdw11:	Feature specific command dword11 field
 * @data_len:	Length of feature data, if applicable, in bytes
 * @data:	User address of feature data, if applicable
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @uuidx:	UUID Index for differentiating vendor specific encoding
 */
struct nvme_get_features_args {
	__u32 *result;
	void *data;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	enum nvme_get_features_sel sel;
	__u32 cdw11;
	__u32 data_len;
	__u8 fid;
	__u8 uuidx;
};

/**
 * struct nvme_capacity_mgmt_args - Arguments for the NVMe Capacity Management command
 * @result:	If successful, the CQE dword0 value
 * @args_size:	Size of &struct nvme_capacity_mgmt_args
 * @cdw11:	Least significant 32 bits of the capacity in bytes of the
 *		Endurance Group or NVM Set to be created
 * @cdw12:	Most significant 32 bits of the capacity in bytes of the
 *		Endurance Group or NVM Set to be created
 * @timeout:	Timeout in ms
 * @element_id:	Value specific to the value of the Operation field
 * @op:		Operation to be performed by the controller
 */
struct nvme_capacity_mgmt_args {
	__u32 *result;
	int args_size;
	__u32 timeout;
	__u32 cdw11;
	__u32 cdw12;
	__u16 element_id;
	__u8 op;
};

/**
 * struct nvme_lockdown_args - Arguments for the NVME Lockdown command
 * @args_size:	Size of &struct nvme_lockdown_args
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms (0 for default timeout)
 * @scp:	Scope of the command
 * @prhbt:	Prohibit or allow the command opcode or Set Features command
 * @ifc:	Affected interface
 * @ofi:	Opcode or Feature Identifier
 * @uuidx:	UUID Index if controller supports this id selection method
 */
struct nvme_lockdown_args {
	__u32 *result;
	int args_size;
	__u32 timeout;
	__u8 scp;
	__u8 prhbt;
	__u8 ifc;
	__u8 ofi;
	__u8 uuidx;
};
#endif /* _LIBNVME_API_TYPES_H */
