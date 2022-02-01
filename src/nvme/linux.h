// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_LINUX_H
#define _LIBNVME_LINUX_H

#include <stddef.h>

#include "types.h"

/**
 * nvme_fw_download_seq() -
 * @fd:     File descriptor of nvme device
 * @size:   Total size of the firmware image to transfer
 * @xfer:   Maximum size to send with each partial transfer
 * @offset: Starting offset to send with this firmware downlaod
 * @buf:    Address of buffer containing all or part of the firmware image.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf);

/**
 * nvme_get_ctrl_telemetry() -
 * @fd:	   File descriptor of nvme device
 * @rae:   Retain asynchronous events
 * @log:   On success, set to the value of the allocated and retreived log.
 * @da:    log page data area, valid values: 1, 2, 3, and 4
 * @size:  Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log,
		int da, size_t *size);

/**
 * nvme_get_host_telemetry() -
 * @fd:	  File descriptor of nvme device
 * @log:  On success, set to the value of the allocated and retreived log.
 * @da:   log page data area, valid values: 1, 2, 3, and 4
 * @size: Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_host_telemetry(int fd,  struct nvme_telemetry_log **log,
		int da, size_t *size);

/**
 * nvme_get_new_host_telemetry() -
 * @fd:   File descriptor of nvme device
 * @log:  On success, set to the value of the allocated and retreived log.
 * @da:   log page data area, valid values: 1, 2, 3, and 4
 * @size: Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_new_host_telemetry(int fd,  struct nvme_telemetry_log **log,
		int da, size_t *size);

/**
 * nvme_get_log_page() -
 * @fd:	      File descriptor of nvme device
 * @nsid:     Namespace Identifier, if applicable.
 * @log_id:   Log Identifier, see &enum nvme_cmd_get_log_lid.
 * @rae:      Retain asynchronous events
 * @xfer_len: Max log transfer size per request to split the total.
 * @data_len: Total length of the log to transfer.
 * @data:     User address of at least &data_len to store the log.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		      __u32 xfer_len, __u32 data_len, void *data);

/**
 * nvme_get_log_page_padded() -
 * @fd:	      File descriptor of nvme device
 * @nsid:     Namespace Identifier, if applicable.
 * @log_id:   Log Identifier, see &enum nvme_cmd_get_log_lid.
 * @rae:      Retain asynchronous events
 * @data_len: Total length of the log to transfer.
 * @data:     User address of at least &data_len to store the log.
 *
 * Calls nvme_get_log_page() with a default 4k transfer length, as that is
 * guarnateed by the protocol to be a safe transfer size.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_page_padded(int fd, __u32 nsid, __u8 log_id, bool rae,
			     __u32 data_len, void *data);

/**
 * nvme_get_ana_log_len() - Retreive size of the current ANA log
 * @fd:		File descriptor of nvme device
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_get_logical_block_size() - Retrieve block size
 * @fd:		File descriptor of nvme device
 * @blksize:	Pointer to where the block size will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_logical_block_size(int fd, __u32 nsid, int *blksize);

/**
 * nvme_get_lba_status_log() - Retreive the LBA Status log page
 * @fd:	   File descriptor of the nvme device
 * @rae:   Retain asynchronous events
 * @log:   On success, set to the value of the allocated and retreived log.
 */
int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_namespace_detach_ctrls() - Detach namespace from controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the detach action
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @name: The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * errno set otherwise.
 */
int nvme_open(const char *name);

/**
 * enum nvme_hmac_alg - HMAC algorithm
 * NVME_HMAC_ALG_NONE:		No HMAC algorithm
 * NVME_HMAC_ALG_SHA2_256:	SHA2-256
 * NVME_HMAC_ALG_SHA2_384:	SHA2-384
 * NVME_HMAC_ALG_SHA2_512:	SHA2-512
 */
enum nvme_hmac_alg {
	NVME_HMAC_ALG_NONE	= 0,
	NVME_HMAC_ALG_SHA2_256	= 1,
	NVME_HMAC_ALG_SHA2_384	= 2,
	NVME_HMAC_ALG_SHA2_512	= 3,
};

/**
 * nvme_gen_dhchap_key() - DH-HMAC-CHAP key generation
 * @hostnqn:	Host NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @key_len:	Output key lenght
 * @secret:	Secret to used for digest
 * @key:	Generated DH-HMAC-CHAP key
 *
 * Return: If key generation was successful the function returns 0 or
 * -1 with errno set otherwise.
 */
int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key);

#endif /* _LIBNVME_LINUX_H */
