// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_FABRICS_H
#define _LIBNVME_FABRICS_H

#include <stdbool.h>
#include <stdint.h>
#include "tree.h"

/**
 * DOC: fabrics.h
 *
 * Fabrics-specific definitions.
 */

/* default to 600 seconds of reconnect attempts before giving up */
#define NVMF_DEF_CTRL_LOSS_TMO		600

/**
 * struct nvme_fabrics_config - Defines all linux nvme fabrics initiator options
 * @host_traddr:	Host transport address
 * @host_iface:		Host interface name
 * @queue_size:		Number of IO queue entries
 * @nr_io_queues:	Number of controller IO queues to establish
 * @reconnect_delay:	Time between two consecutive reconnect attempts.
 * @ctrl_loss_tmo:	Override the default controller reconnect attempt timeout in seconds
 * @fast_io_fail_tmo:	Set the fast I/O fail timeout in seconds.
 * @keep_alive_tmo:	Override the default keep-alive-timeout to this value in seconds
 * @nr_write_queues:	Number of queues to use for exclusively for writing
 * @nr_poll_queues:	Number of queues to reserve for polling completions
 * @tos:		Type of service
 * @duplicate_connect:	Allow multiple connections to the same target
 * @disable_sqflow:	Disable controller sq flow control
 * @hdr_digest:		Generate/verify header digest (TCP)
 * @data_digest:	Generate/verify data digest (TCP)
 * @tls:		Start TLS on the connection (TCP)
 */
struct nvme_fabrics_config {
	char *host_traddr;
	char *host_iface;
	int queue_size;
	int nr_io_queues;
	int reconnect_delay;
	int ctrl_loss_tmo;
	int fast_io_fail_tmo;
	int keep_alive_tmo;
	int nr_write_queues;
	int nr_poll_queues;
	int tos;

	bool duplicate_connect;
	bool disable_sqflow;
	bool hdr_digest;
	bool data_digest;
	bool tls;
};

/**
 * nvmf_trtype_str() - Decode TRTYPE field
 * @trtype: value to be decoded
 *
 * Decode the transport type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_trtype_str(__u8 trtype);

/**
 * nvmf_adrfam_str() - Decode ADRFAM field
 * @adrfam: value to be decoded
 *
 * Decode the address family field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_adrfam_str(__u8 adrfam);

/**
 * nvmf_subtype_str() - Decode SUBTYPE field
 * @subtype: value to be decoded
 *
 * Decode the subsystem type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_subtype_str(__u8 subtype);

/**
 * nvmf_treq_str() - Decode TREQ field
 * @treq: value to be decoded
 *
 * Decode the transport requirements field in the
 * discovery log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_treq_str(__u8 treq);

/**
 * nvmf_eflags_str() - Decode EFLAGS field
 * @eflags: value to be decoded
 *
 * Decode the EFLAGS field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *nvmf_eflags_str(__u16 eflags);

/**
 * nvmf_sectype_str() - Decode SECTYPE field
 * @sectype: value to be decoded
 *
 * Decode the SECTYPE field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *nvmf_sectype_str(__u8 sectype);

/**
 * nvmf_prtype_str() - Decode RDMA Provider type field
 * @prtype: value to be decoded
 *
 * Decode the RDMA Provider type field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_prtype_str(__u8 prtype);

/**
 * nvmf_qptype_str() - Decode RDMA QP Service type field
 * @qptype: value to be decoded
 *
 * Decode the RDMA QP Service type field in the discovery log page
 * entry.
 *
 * Return: decoded string
 */
const char *nvmf_qptype_str(__u8 qptype);

/**
 * nvmf_cms_str() - Decode RDMA connection management service field
 * @cms: value to be decoded
 *
 * Decode the RDMA connection management service field in the discovery
 * log page entry.
 *
 * Return: decoded string
 */
const char *nvmf_cms_str(__u8 cms);

/**
 * nvmf_default_config() - Default values for fabrics configuration
 * @cfg: config values to set
 *
 * Initializes @cfg with default values.
 */
void nvmf_default_config(struct nvme_fabrics_config *cfg);

/**
 * nvmf_update_config() - Update fabrics configuration values
 * @c:          Controller to be modified
 * @cfg:        Updated configuration values
 *
 * Updates the values from @c with the configuration values from @cfg;
 * all non-default values from @cfg will overwrite the values in @c.
 */
void nvmf_update_config(nvme_ctrl_t c, const struct nvme_fabrics_config *cfg);

/**
 * nvmf_add_ctrl() - Connect a controller and update topology
 * @h:		Host to which the controller should be attached
 * @c:		Controller to be connected
 * @cfg:	Default configuration for the controller
 *
 * Issues a 'connect' command to the NVMe-oF controller and inserts @c
 * into the topology using @h as parent.
 * @c must be initialized and not connected to the topology.
 *
 * Return: 0 on success; on failure errno is set and -1 is returned.
 */
int nvmf_add_ctrl(nvme_host_t h, nvme_ctrl_t c,
		  const struct nvme_fabrics_config *cfg);

/**
 * nvmf_get_discovery_log() - Return the discovery log page
 * @c:			Discover controller to use
 * @logp:		Pointer to the log page to be returned
 * @max_retries:	maximum number of log page entries to be returned
 *
 * Return: 0 on success; on failure -1 is returned and errno is set
 */
int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp,
			   int max_retries);

/**
 * nvmf_hostnqn_generate() - Generate a machine specific host nqn
 * Returns: An nvm namespace qualified name string based on the machine
 * identifier, or NULL if not successful.
 */
char *nvmf_hostnqn_generate();

/**
 * nvmf_hostnqn_from_file() - Reads the host nvm qualified name from the config
 *			      default location in @SYSCONFDIR@/nvme/
 * Return: The host nqn, or NULL if unsuccessful. If found, the caller
 * is responsible to free the string.
 */
char *nvmf_hostnqn_from_file();

/**
 * nvmf_hostid_from_file() - Reads the host identifier from the config default
 *			     location in @SYSCONFDIR@/nvme/.
 * Return: The host identifier, or NULL if unsuccessful. If found, the caller
 *	   is responsible to free the string.
 */
char *nvmf_hostid_from_file();

/**
 * nvmf_connect_disc_entry() - Connect controller based on the discovery log page entry
 * @h:		Host to which the controller should be connected
 * @e:		Discovery log page entry
 * @defcfg:	Default configuration to be used for the new controller
 * @discover:	Set to 'true' if the new controller is a discovery controller
 *
 * Return: Pointer to the new controller
 */
nvme_ctrl_t nvmf_connect_disc_entry(nvme_host_t h,
				    struct nvmf_disc_log_entry *e,
			            const struct nvme_fabrics_config *defcfg,
				    bool *discover);

/**
 * struct nvmf_connect_disc_entry2_args - Arguments for the nvmf_connect_disc_entry2 command
 * @defcfg:	Default configuration to be used for the new controller
 * @discover:	Set to 'true' if the new controller is a discovery controller
 * @dhchap_ctrl_key: DH-HMAC-CHAP ctrl key
 * @args_size:	Size of &struct nvmf_connect_disc_entry2_args
 */
struct nvmf_connect_disc_entry2_args
{
	const struct nvme_fabrics_config *defcfg;
	bool		*discover;
	const char	*dhchap_ctrl_key;
	int		args_size;
};

/**
 * nvmf_connect_disc_entry2() - Connect controller based on the discovery log page entry
 * @h:		Host to which the controller should be connected
 * @e:		Discovery log page entry
 * @args:	&struct nvmf_connect_disc_entry2_args argument structure
 *
 * Return: Pointer to the  controller
 */
nvme_ctrl_t nvmf_connect_disc_entry2(nvme_host_t h,
				     struct nvmf_disc_log_entry *e,
				     struct nvmf_connect_disc_entry2_args *args);

/**
 * nvmf_is_registration_supported - check whether registration can be performed.
 * @c:	Controller instance
 *
 * Only discovery controllers (DC) that comply with TP8010 support
 * explicit registration with the DIM PDU. These can be identified by
 * looking at the value of a dctype in the Identify command
 * response. A value of 1 (DDC) or 2 (CDC) indicates that the DC
 * supports explicit registration.
 *
 * Return: true if controller supports explicit registration. false
 * otherwise.
 */
bool nvmf_is_registration_supported(nvme_ctrl_t c);

/**
 * nvmf_register_ctrl() - Perform registration task with a DC
 * @c:		Controller instance
 * @tas:	Task field of the Command Dword 10 (cdw10). Indicates whether to
 *		perform a Registration, Deregistration, or Registration-update.
 * @result:	The command-specific result returned by the DC upon command
 *		completion.
 *
 * Perform registration task with a Discovery Controller (DC). Three
 * tasks are supported: register, deregister, and registration update.
 *
 * Return: 0 on success; on failure -1 is returned and errno is set
 */
int nvmf_register_ctrl(nvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result);

#endif /* _LIBNVME_FABRICS_H */
