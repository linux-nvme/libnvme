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
 * struct nvme_directive_send_args - Arguments for the NVMe Directive Send command
 * @result:	If successful, the CQE dword0 value
 * @data:	Data payload to be send
 * @args_size:	Size of &struct nvme_directive_send_args
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @cdw12:	Directive specific command dword12
 * @data_len:	Length of data payload in bytes
 * @dspec:	Directive specific field
 */
struct nvme_directive_send_args {
	__u32 *result;
	void *data;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	enum nvme_directive_send_doper doper;
	enum nvme_directive_dtype dtype;
	__u32 cdw12;
	__u32 data_len;
	__u16 dspec;
};

/**
 * struct nvme_directive_recv_args - Arguments for the NVMe Directive Receive command
 * @result:	If successful, the CQE dword0 value
 * @data:	Userspace address of data payload
 * @args_size:	Size of &struct nvme_directive_recv_args
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @cdw12:	Directive specific command dword12
 * @data_len:	Length of data payload in bytes
 * @dspec:	Directive specific field
 */
struct nvme_directive_recv_args {
	__u32 *result;
	void *data;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	enum nvme_directive_receive_doper doper;
	enum nvme_directive_dtype dtype;
	__u32 cdw12;
	__u32 data_len;
	__u16 dspec;
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

/**
 * struct nvme_set_property_args - Arguments for NVMe Set Property command
 * @args_size:	Size of &struct nvme_set_property_args
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms
 * @offset:	Property offset from the base to set
 * @value:	The value to set the property
 */
struct nvme_set_property_args {
	__u64 value;
	__u32 *result;
	int args_size;
	__u32 timeout;
	int offset;
};

/**
 * struct nvme_get_property_args - Arguments for NVMe Get Property command
 * @value:	Where the property's value will be stored on success
 * @args_size:	Size of &struct nvme_get_property_args
 * @offset:	Property offset from the base to retrieve
 * @timeout:	Timeout in ms
 */
struct nvme_get_property_args {
	__u64 *value;
	int args_size;
	__u32 timeout;
	int offset;
};

/**
 * struct nvme_sanitize_nvm_args - Arguments for the NVMe Sanitize NVM command
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_sanitize_nvm_args
 * @timeout:	Timeout in ms
 * @ovrpat:	Overwrite pattern
 * @sanact:	Sanitize action, see &enum nvme_sanitize_sanact
 * @ause:	Set to allow unrestricted sanitize exit
 * @owpass:	Overwrite pass count
 * @oipbp:	Set to overwrite invert pattern between passes
 * @nodas:	Set to not deallocate blocks after sanitizing
 * @emvs:	Set to enter media verification state
 */
struct nvme_sanitize_nvm_args {
	__u32 *result;
	int args_size;
	__u32 timeout;
	enum nvme_sanitize_sanact sanact;
	__u32 ovrpat;
	bool ause;
	__u8 owpass;
	bool oipbp;
	bool nodas;
	bool emvs;
};

/**
 * struct nvme_dev_self_test_args - Arguments for the NVMe Device Self Test command
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_dev_self_test_args
 * @nsid:	Namespace ID to test
 * @stc:	Self test code, see &enum nvme_dst_stc
 * @timeout:	Timeout in ms
 */
struct nvme_dev_self_test_args {
	__u32 *result;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	enum nvme_dst_stc stc;
};

/**
 * struct nvme_virtual_mgmt_args - Arguments for the NVMe Virtualization
 *			    resource management command
 * @args_size:	Size of &struct nvme_virtual_mgmt_args
 * @result:	If successful, the CQE dword0
 * @timeout:	Timeout in ms
 * @act:	Virtual resource action, see &enum nvme_virt_mgmt_act
 * @rt:		Resource type to modify, see &enum nvme_virt_mgmt_rt
 * @cntlid:	Controller id for which resources are bing modified
 * @nr:		Number of resources being allocated or assigned
 */
struct nvme_virtual_mgmt_args {
	__u32 *result;
	int args_size;
	__u32 timeout;
	enum nvme_virt_mgmt_act act;
	enum nvme_virt_mgmt_rt rt;
	__u16 cntlid;
	__u16 nr;
};
#endif /* _LIBNVME_API_TYPES_H */
