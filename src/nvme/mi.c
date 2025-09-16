// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <ccan/ccan/minmax/minmax.h>
#include <ccan/endian/endian.h>

#include "log.h"
#include "mi.h"
#include "linux.h"
#include "private.h"

#define NUM_ENABLES    (256u)

_Static_assert(sizeof(struct nvme_mi_aem_supported_list_header) == 5,
	"size_of_nvme_mi_aem_supported_list_header_is_not_5_bytes");
_Static_assert(sizeof(struct nvme_mi_aem_supported_item) == 3,
	"sizeof_nvme_mi_aem_supported_item_is_not_3_bytes");
_Static_assert(sizeof(struct nvme_mi_aem_enable_item) == 3,
	"size_of_ae_enable_item_t_is_not_3_bytes");
_Static_assert(sizeof(struct nvme_mi_aem_enable_list_header) == 5,
	"size_of_nvme_mi_aem_enable_list_header_is_not_5_bytes");
_Static_assert(sizeof(struct nvme_mi_aem_occ_data) == 9,
	"size_of_nvme_mi_aem_occ_data_is_not_9_bytes");
_Static_assert(sizeof(struct nvme_mi_aem_occ_list_hdr) == 7,
	"size_of_nvme_mi_aem_occ_list_hdr_is_not_7_bytes");

static int nvme_mi_get_async_message(nvme_mi_ep_t ep,
	struct nvme_mi_aem_msg *aem_msg, size_t *aem_msg_len);

static const int default_timeout = 1000; /* milliseconds; endpoints may
					    override */

static bool nvme_mi_probe_enabled_default(void)
{
	char *val;

	val = getenv("LIBNVME_MI_PROBE_ENABLED");
	if (!val)
		return true;

	return strcmp(val, "0") &&
		strcasecmp(val, "false") &&
		strncasecmp(val, "disable", 7);

}

static int parse_devname(const char *dev, unsigned int *net, uint8_t *eid,
			unsigned int *ctrl)
{
	int rc;

	/* <net>,<eid>:<ctrl-id> form */
	rc = sscanf(dev, "mctp:%u,%hhu:%u", net, eid, ctrl);
	if (rc == 3)
		return 0;

	/* <net>,<eid> form, implicit ctrl-id = 0 */
	*ctrl = 0;
	rc = sscanf(dev, "mctp:%u,%hhu", net, eid);
	if (rc == 2)
		return 0;

	return -EINVAL;
}

int __nvme_link_init_mi(nvme_link_t l)
{
	if (l->type != NVME_LINK_TYPE_UNKNOWN)
		return -EALREADY;

	l->type = NVME_LINK_TYPE_MI;

	return 0;
}

int __nvme_link_open_mi(nvme_link_t l, const char *devname)
{
	unsigned int rc, net, ctrl_id;
	unsigned char eid;
	struct nvme_mi_ep *ep;

	rc = __nvme_link_init_mi(l);
	if (rc)
		return rc;

	rc = parse_devname(devname, &net, &eid, &ctrl_id);
		return rc;

	ep = nvme_mi_open_mctp(l->root, net, eid);
	if (!ep)
		return -EINVAL;

	return 0;
}

void __nvme_link_close_mi(nvme_link_t link)
{
	list_del(&link->ep_entry);
	free(link);
}

/* MI-equivalent of nvme_create_root, but avoids clashing symbol names
 * when linking against both libnvme and libnvme-mi.
 */
nvme_root_t nvme_mi_create_root(FILE *fp, int log_level)
{
	struct nvme_root *r;
	int fd;

	r = calloc(1, sizeof(*r));
	if (!r)
		return NULL;

	if (fp) {
		fd = fileno(fp);
		if (fd < 0) {
			free(r);
			return NULL;
		}
	} else
		fd = STDERR_FILENO;

	r->log.fd = fd;
	r->log.level = log_level;

	r->mi_probe_enabled = nvme_mi_probe_enabled_default();

	list_head_init(&r->hosts);
	list_head_init(&r->endpoints);

	return r;
}

void nvme_mi_free_root(nvme_root_t root)
{
	nvme_mi_ep_t ep, tmp;

	nvme_mi_for_each_endpoint_safe(root, ep, tmp)
		nvme_mi_close(ep);

	free(root);
}

void nvme_mi_set_probe_enabled(nvme_root_t root, bool enabled)
{
	root->mi_probe_enabled = enabled;
}

static void nvme_mi_record_resp_time(struct nvme_mi_ep *ep)
{
	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &ep->last_resp_time);
	ep->last_resp_time_valid = !rc;
}

static bool nvme_mi_compare_vid_mn(struct nvme_mi_ep *ep,
				   struct nvme_id_ctrl *id,
				   __u16 vid, const char *mn)

{
	int len;

	len = strlen(mn);
	if (len >= sizeof(id->mn)) {
		nvme_msg(ep->root, LOG_ERR,
			 "Internal error: invalid model number for %s\n",
			 __func__);
		return false;
	}

	return le16_to_cpu(id->vid) == vid && !strncmp(id->mn, mn, len);
}

static void __nvme_mi_format_mn(struct nvme_id_ctrl *id,
				char *mn, size_t mn_len)
{
	const size_t id_mn_size = sizeof(id->mn);
	int i;

	/* A BUILD_ASSERT() would be nice here, but we're not const enough for
	 * that
	 */
	if (mn_len <= id_mn_size)
		abort();

	memcpy(mn, id->mn, id_mn_size);
	mn[id_mn_size] = '\0';

	for (i = id_mn_size - 1; i >= 0; i--) {
		if (mn[i] != '\0' && mn[i] != ' ')
			break;
		mn[i] = '\0';
	}
}

#define nvme_mi_format_mn(id, m) __nvme_mi_format_mn(id, m, sizeof(m))

void nvme_mi_ep_probe(struct nvme_mi_ep *ep)
{
	struct nvme_id_ctrl id = { 0 };
	struct nvme_link *link;
	int rc;

	/* Ensure the probe occurs at most once. This isn't just to mitigate doubling
	 * a linear stream of commands, it also terminates recursion via the
	 * nvme_mi_submit() call issued by nvme_mi_admin_identify_partial() below.
	 */
	if (ep->quirks_probed)
		return;

	/* Mark ep->quirks as valid. Note that for the purpose of quirk probing,
	 * the quirk probe itself cannot rely on quirks, and so the fact that none are
	 * yet set is desirable. The request that triggered nvme_mi_submit() will have
	 * an initialised ep->quirks when we return from the root probe call.
	 */
	ep->quirks_probed = true;

	if (!ep->root->mi_probe_enabled)
		return;

	/* start with no quirks, detect as we go */
	ep->quirks = 0;

	link = nvme_mi_init_link(ep, 0);
	if (!link)
		return;

	/* Do enough of an identify (assuming controller 0) to retrieve
	 * device and firmware identification information. This gives us the
	 * following fields in id:
	 *
	 *  - vid (PCI vendor ID)
	 *  - ssvid (PCI subsystem vendor ID)
	 *  - sn (Serial number)
	 *  - mn (Model number)
	 *  - fr (Firmware revision)
	 *
	 * all other fields - rab and onwards - will be zero!
	 */
	rc = nvme_identify_partial(link, NVME_NSID_NONE, 0, NVME_IDENTIFY_CNS_CTRL,
				   NVME_CSI_NVM, 0, 0, &id,
				   offsetof(struct nvme_id_ctrl, rab),  NULL);
	if (rc) {
		nvme_msg(ep->root, LOG_WARNING,
			 "Identify Controller failed, no quirks applied\n");
		goto out_close;
	}

	/* Samsung MZUL2512: cannot receive commands sent within ~1ms of
	 * the previous response. Set an inter-command delay of 1.2ms for
	 * a little extra tolerance.
	 */
	if (nvme_mi_compare_vid_mn(ep, &id, 0x144d, "MZUL2512HCJQ")) {
		ep->quirks |= NVME_QUIRK_MIN_INTER_COMMAND_TIME;
		ep->inter_command_us = 1200;
	}

	/* If we're quirking for the inter-command time, record the last
	 * command time now, so we don't conflict with the just-sent identify.
	 */
	if (ep->quirks & NVME_QUIRK_MIN_INTER_COMMAND_TIME)
		nvme_mi_record_resp_time(ep);

	if (ep->quirks) {
		char tmp[sizeof(id.mn) + 1];

		nvme_mi_format_mn(&id, tmp);
		nvme_msg(ep->root, LOG_DEBUG,
			 "device %02x:%s: applying quirks 0x%08lx\n",
			 id.vid, tmp, ep->quirks);
	}

out_close:
	nvme_close(link);
}

static const int nsec_per_sec = 1000 * 1000 * 1000;
/* timercmp and timersub, but for struct timespec */
#define timespec_cmp(a, b, CMP)						\
	(((a)->tv_sec == (b)->tv_sec)					\
		? ((a)->tv_nsec CMP (b)->tv_nsec)			\
		: ((a)->tv_sec CMP (b)->tv_sec))

#define timespec_sub(a, b, result)					\
	do {								\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
		(result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;	\
		if ((result)->tv_nsec < 0) {				\
			--(result)->tv_sec;				\
			(result)->tv_nsec += nsec_per_sec;		\
		}							\
	} while (0)

static void nvme_mi_insert_delay(struct nvme_mi_ep *ep)
{
	struct timespec now, next, delay;
	int rc;

	if (!ep->last_resp_time_valid)
		return;

	/* calculate earliest next command time */
	next.tv_nsec = ep->last_resp_time.tv_nsec + ep->inter_command_us * 1000;
	next.tv_sec = ep->last_resp_time.tv_sec;
	if (next.tv_nsec > nsec_per_sec) {
		next.tv_nsec -= nsec_per_sec;
		next.tv_sec += 1;
	}

	rc = clock_gettime(CLOCK_MONOTONIC, &now);
	if (rc) {
		/* not much we can do; continue immediately */
		return;
	}

	if (timespec_cmp(&now, &next, >=))
		return;

	timespec_sub(&next, &now, &delay);

	nanosleep(&delay, NULL);
}

struct nvme_mi_ep *nvme_mi_init_ep(nvme_root_t root)
{
	struct nvme_mi_ep *ep;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return NULL;

	list_node_init(&ep->root_entry);
	ep->root = root;
	ep->quirks_probed = false;
	ep->controllers_scanned = false;
	ep->timeout = default_timeout;
	ep->mprt_max = 0;
	list_head_init(&ep->controllers);

	list_add(&root->endpoints, &ep->root_entry);

	return ep;
}

int nvme_mi_ep_set_timeout(nvme_mi_ep_t ep, unsigned int timeout_ms)
{
	if (ep->transport->check_timeout) {
		int rc;
		rc = ep->transport->check_timeout(ep, timeout_ms);
		if (rc)
			return rc;
	}

	ep->timeout = timeout_ms;
	return 0;
}

void nvme_mi_ep_set_mprt_max(nvme_mi_ep_t ep, unsigned int mprt_max_ms)
{
	ep->mprt_max = mprt_max_ms;
}

unsigned int nvme_mi_ep_get_timeout(nvme_mi_ep_t ep)
{
	return ep->timeout;
}

static bool nvme_mi_ep_has_quirk(nvme_mi_ep_t ep, unsigned long quirk)
{
	return ep->quirks & quirk;
}

struct nvme_link *nvme_mi_init_link(nvme_mi_ep_t ep, __u16 ctrl_id)
{
	struct nvme_link *link;

	link = __nvme_create_link(ep->root);
 	if (!link)
		 NULL;

	__nvme_link_init_mi(link);

	link->ep = ep;
	link->id = ctrl_id;

	list_add_tail(&ep->controllers, &link->ep_entry);

	return link;
}

__u16 nvme_mi_ctrl_id(nvme_link_t link)
{
	return link->id;
}

int nvme_mi_scan_ep(nvme_mi_ep_t ep, bool force_rescan)
{
	struct nvme_ctrl_list list;
	unsigned int i, n_ctrl;
	int rc;

	if (ep->controllers_scanned) {
		if (force_rescan) {
			struct nvme_link *link, *tmp;
			nvme_mi_for_each_link_safe(ep, link, tmp)
				nvme_close(link);
		} else {
			return 0;
		}
	}

	rc = nvme_mi_mi_read_mi_data_ctrl_list(ep, 0, &list);
	if (rc)
		return rc;

	n_ctrl = le16_to_cpu(list.num);
	if (n_ctrl > NVME_ID_CTRL_LIST_MAX)
		return -EPROTO;

	for (i = 0; i < n_ctrl; i++) {
		struct nvme_link *link;
		__u16 id;

		id = le16_to_cpu(list.identifier[i]);

		link = nvme_mi_init_link(ep, id);
		if (!link)
			break;
	}

	ep->controllers_scanned = true;
	return 0;
}

__u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len)
{
	int i;

	while (len--) {
		crc ^= *(unsigned char *)(data++);
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78 : 0);
	}
	return crc;
}

static void nvme_mi_calc_req_mic(struct nvme_mi_req *req)
{
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, req->hdr, req->hdr_len);
	crc = nvme_mi_crc32_update(crc, req->data, req->data_len);

	req->mic = ~crc;
}

/* returns zero on correct MIC */
static int nvme_mi_verify_resp_mic(struct nvme_mi_resp *resp)
{
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, resp->hdr, resp->hdr_len);
	crc = nvme_mi_crc32_update(crc, resp->data, resp->data_len);

	return resp->mic != ~crc;
}

__attribute__((weak)) void *nvme_mi_submit_entry(__u8 type, const struct nvme_mi_msg_hdr *hdr,
						 size_t hdr_len, const void *data, size_t data_len)
{
	return NULL;
}

__attribute__((weak)) void nvme_mi_submit_exit(__u8 type, const struct nvme_mi_msg_hdr *hdr,
					       size_t hdr_len, const void *data, size_t data_len,
					       void *user_data) { }


int nvme_mi_async_read(nvme_mi_ep_t ep, struct nvme_mi_resp *resp)
{
	if (nvme_mi_ep_has_quirk(ep, NVME_QUIRK_MIN_INTER_COMMAND_TIME))
		nvme_mi_record_resp_time(ep);

	int rc = ep->transport->aem_read(ep, resp);

	if (rc == EWOULDBLOCK) {
		//Sometimes we might get owned tag data from the wrong endpoint.
		//This isn't an error, but we shouldn't process it here
		resp->data_len = 0;//No data to process
		return 0;
	} else if (rc) {
		nvme_msg(ep->root, LOG_INFO, "transport failure\n");
		return rc;
	}

	if (ep->transport->mic_enabled) {
		rc = nvme_mi_verify_resp_mic(resp);
		if (rc) {
			nvme_msg(ep->root, LOG_WARNING, "crc mismatch\n");
			return -EBADMSG;
		}
	}

	//TODO: There's a bunch of overlap with the nvme_mi_submit.  Maybe we make common helpers

	/* basic response checks */
	if (resp->hdr_len < sizeof(struct nvme_mi_msg_hdr)) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Bad response header len: %zd\n", resp->hdr_len);
		return -EPROTO;
	}

	if (resp->hdr->type != NVME_MI_MSGTYPE_NVME) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Invalid message type 0x%02x\n", resp->hdr->type);
		return -EPROTO;
	}

	if (!(resp->hdr->nmp & ~(NVME_MI_ROR_REQ << 7))) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "ROR value in response indicates a response\n");
		return -EIO;
	}

	if (!(resp->hdr->nmp & (NVME_MI_MT_AE << 3))) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "NMIMT does not indicate AEM\n");
		resp->data_len = 0;//No data to process
		return 0;
	}

	return 0;
}


int nvme_mi_submit(nvme_mi_ep_t ep, struct nvme_mi_req *req,
		   struct nvme_mi_resp *resp)
{
	int rc;
	void *user_data;

	user_data = nvme_mi_submit_entry(req->hdr->type, req->hdr, req->hdr_len, req->data,
					 req->data_len);

	if (req->hdr_len < sizeof(struct nvme_mi_msg_hdr))
		return -EINVAL;

	if (req->hdr_len & 0x3)
		return -EINVAL;

	if (resp->hdr_len < sizeof(struct nvme_mi_msg_hdr))
		return -EINVAL;

	if (resp->hdr_len & 0x3)
		return -EINVAL;

	nvme_mi_ep_probe(ep);

	if (ep->transport->mic_enabled)
		nvme_mi_calc_req_mic(req);

	if (nvme_mi_ep_has_quirk(ep, NVME_QUIRK_MIN_INTER_COMMAND_TIME))
		nvme_mi_insert_delay(ep);

	rc = ep->transport->submit(ep, req, resp);

	if (nvme_mi_ep_has_quirk(ep, NVME_QUIRK_MIN_INTER_COMMAND_TIME))
		nvme_mi_record_resp_time(ep);

	if (rc) {
		nvme_msg(ep->root, LOG_INFO, "transport failure\n");
		return rc;
	}

	if (ep->transport->mic_enabled) {
		rc = nvme_mi_verify_resp_mic(resp);
		if (rc) {
			nvme_msg(ep->root, LOG_WARNING, "crc mismatch\n");
			return -EBADMSG;
		}
	}

	/* basic response checks */
	if (resp->hdr_len < sizeof(struct nvme_mi_msg_hdr)) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Bad response header len: %zd\n", resp->hdr_len);
		return -EPROTO;
	}

	if (resp->hdr->type != NVME_MI_MSGTYPE_NVME) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Invalid message type 0x%02x\n", resp->hdr->type);
		return -EPROTO;
	}

	if (!(resp->hdr->nmp & (NVME_MI_ROR_RSP << 7))) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "ROR value in response indicates a request\n");
		return -EIO;
	}

	if ((resp->hdr->nmp & 0x1) != (req->hdr->nmp & 0x1)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "Command slot mismatch: req %d, resp %d\n",
			 req->hdr->nmp & 0x1,
			 resp->hdr->nmp & 0x1);
		return -EIO;
	}

	nvme_mi_submit_exit(resp->hdr->type, resp->hdr, resp->hdr_len, resp->data, resp->data_len,
			    user_data);

	return 0;
}

int nvme_mi_set_csi(nvme_mi_ep_t ep, uint8_t csi)
{
	uint8_t csi_bit = (csi) ? 1 : 0;

	if (nvme_mi_ep_has_quirk(ep, NVME_QUIRK_CSI_1_NOT_SUPPORTED) && csi_bit)
		return -1;

	ep->csi = csi_bit;

	return 0;
}

static void nvme_mi_admin_init_req(nvme_mi_ep_t ep,
				   struct nvme_mi_req *req,
				   struct nvme_mi_admin_req_hdr *hdr,
				   __u16 ctrl_id, __u8 opcode)
{
	memset(req, 0, sizeof(*req));
	memset(hdr, 0, sizeof(*hdr));

	hdr->hdr.type = NVME_MI_MSGTYPE_NVME;
	hdr->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_ADMIN << 3) |
		(ep->csi & 1);
	hdr->opcode = opcode;
	hdr->ctrl_id = cpu_to_le16(ctrl_id);

	req->hdr = &hdr->hdr;
	req->hdr_len = sizeof(*hdr);
}

static void nvme_mi_admin_init_resp(struct nvme_mi_resp *resp,
				    struct nvme_mi_admin_resp_hdr *hdr)
{
	memset(resp, 0, sizeof(*resp));
	resp->hdr = &hdr->hdr;
	resp->hdr_len = sizeof(*hdr);
}

static void nvme_mi_control_init_req(nvme_mi_ep_t ep,
				    struct nvme_mi_req *req,
				    struct nvme_mi_control_req *control_req,
				    __u8 opcode, __u16 cpsp)
{
	memset(req, 0, sizeof(*req));
	memset(control_req, 0, sizeof(*control_req));

	control_req->hdr.type = NVME_MI_MSGTYPE_NVME;
	control_req->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_CONTROL << 3) |
		(ep->csi & 1);
	control_req->opcode = opcode;
	control_req->cpsp = cpu_to_le16(cpsp);

	req->hdr = &control_req->hdr;
	req->hdr_len = sizeof(*control_req);
}

static void nvme_mi_control_init_resp(struct nvme_mi_resp *resp,
				    struct nvme_mi_control_resp *control_resp)
{
	memset(resp, 0, sizeof(*resp));
	resp->hdr = &control_resp->hdr;
	resp->hdr_len = sizeof(*control_resp);
}

static int nvme_mi_admin_parse_status(struct nvme_mi_resp *resp, __u32 *result)
{
	struct nvme_mi_admin_resp_hdr *admin_hdr;
	struct nvme_mi_msg_resp *resp_hdr;
	__u32 nvme_status;
	__u32 nvme_result;

	/* we have a few different sources of "result" here: the status header
	 * in the MI response, the cdw3 status field, and (command specific)
	 * return values in cdw0. The latter is returned in the result pointer,
	 * the former two generate return values here
	 */

	if (resp->hdr_len < sizeof(*resp_hdr))
		return -EPROTO;
	resp_hdr = (struct nvme_mi_msg_resp *)resp->hdr;

	/* If we have a MI error, we can't be sure there's an admin header
	 * following; return just the MI status, with the status type
	 * indicator of MI.
	 */
	if (resp_hdr->status)
		return resp_hdr->status |
			(NVME_STATUS_TYPE_MI << NVME_STATUS_TYPE_SHIFT);

	/* We shouldn't hit this, as we'd have an error reported earlier.
	 * However, for pointer safety, ensure we have a full admin header
	 */
	if (resp->hdr_len < sizeof(*admin_hdr))
		return -EPROTO;

	admin_hdr = (struct nvme_mi_admin_resp_hdr *)resp->hdr;
	nvme_result = le32_to_cpu(admin_hdr->cdw0);

	/* Shift down 17 here: the SC starts at bit 17, and the NVME_SC_*
	 * definitions align to this bit (and up). The CRD, MORE and DNR
	 * bits are defined accordingly (eg., DNR is 0x4000).
	 */
	nvme_status = le32_to_cpu(admin_hdr->cdw3) >> 17;

	/* the result pointer, optionally stored if the caller needs it */
	if (result)
		*result = nvme_result;

	return nvme_status;
}

static int nvme_mi_control_parse_status(struct nvme_mi_resp *resp, __u16 *cpsr)
{
	struct nvme_mi_control_resp *control_resp;

	if (resp->hdr_len < sizeof(*control_resp))
		return -EPROTO;
	control_resp = (struct nvme_mi_control_resp *)resp->hdr;

	if (control_resp->status)
		return control_resp->status |
			(NVME_STATUS_TYPE_MI << NVME_STATUS_TYPE_SHIFT);

	if (cpsr)
		*cpsr = le16_to_cpu(control_resp->cpsr);

	return control_resp->status;
}

static int nvme_mi_get_async_message(nvme_mi_ep_t ep,
							struct nvme_mi_aem_msg *aem_msg,
							size_t *aem_msg_len)
{
	struct nvme_mi_resp resp;

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &aem_msg->hdr;
	resp.hdr_len = sizeof(struct nvme_mi_msg_hdr);
	resp.data = &aem_msg->occ_list_hdr;
	resp.data_len = *aem_msg_len;

	int rc = nvme_mi_async_read(ep, &resp);

	if (rc)
		return rc;

	*aem_msg_len = resp.data_len;
	return 0;
}


int nvme_mi_admin_xfer(nvme_link_t link,
		       struct nvme_mi_admin_req_hdr *admin_req,
		       size_t req_data_size,
		       struct nvme_mi_admin_resp_hdr *admin_resp,
		       off_t resp_data_offset,
		       size_t *resp_data_size)
{
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	__u32 dlen, doff;
	int rc;

	/* length/offset checks. The common _submit() API will do further
	 * checking on the message lengths too, so these are kept specific
	 * to the requirements of the Admin command set
	 */

	/* NVMe-MI v1.2 imposes a limit of 4096 bytes on the dlen field */
	if (*resp_data_size > 4096)
		return -EINVAL;

	/* we only have 32 bits of offset */
	if (resp_data_offset > 0xffffffff)
		return -EINVAL;

	/* request and response lengths & offset must be aligned */
	if ((req_data_size & 0x3) ||
	    (*resp_data_size & 0x3) ||
	    (resp_data_offset & 0x3))
		return -EINVAL;

	/* bidirectional not permitted (see DLEN definition) */
	if (req_data_size && *resp_data_size)
		return -EINVAL;

	if (!*resp_data_size && resp_data_offset)
		return -EINVAL;

	admin_req->hdr.type = NVME_MI_MSGTYPE_NVME;
	admin_req->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
			     (NVME_MI_MT_ADMIN << 3) |
			     (link->ep->csi & 1);

	admin_req->ctrl_id = cpu_to_le16(link->id);
	memset(&req, 0, sizeof(req));
	req.hdr = &admin_req->hdr;
	req.hdr_len = sizeof(*admin_req);
	req.data = admin_req + 1;
	req.data_len = req_data_size;

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &admin_resp->hdr;
	resp.hdr_len = sizeof(*admin_resp);
	resp.data = admin_resp + 1;
	resp.data_len = *resp_data_size;

	/* limit the response size, specify offset */
	admin_req->flags = 0x3;

	/* dlen and doff have different interpretations depending on the data direction */
	if (req_data_size) {
		dlen = req_data_size & 0xffffffff;
		doff = 0;
	} else {
		dlen = *resp_data_size & 0xffffffff;
		doff = resp_data_offset & 0xffffffff;
	}
	admin_req->dlen = cpu_to_le32(dlen);
	admin_req->doff = cpu_to_le32(doff);

	rc = nvme_mi_submit(link->ep, &req, &resp);
	if (rc)
		return rc;

	*resp_data_size = resp.data_len;

	return 0;
}

int nvme_mi_admin_admin_passthru(nvme_link_t link, __u8 opcode, __u8 flags,
				 __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
				 __u32 cdw10, __u32 cdw11, __u32 cdw12,
				 __u32 cdw13, __u32 cdw14, __u32 cdw15,
				 __u32 data_len, void *data, __u32 metadata_len,
				 void *metadata, __u32 timeout_ms, __u32 *result)
{
	/* Input parameters flags, rsvd, metadata, metadata_len are not used */
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	unsigned int timeout_save;
	int rc;
	int direction = opcode & 0x3;
	bool has_write_data = false;
	bool has_read_data = false;

	if (direction == NVME_DATA_TFR_BIDIRECTIONAL) {
		nvme_msg(link->root, LOG_ERR,
			"nvme_mi_admin_admin_passthru doesn't support bidirectional commands\n");
		return -EINVAL;
	}

	if (data_len > 4096) {
		nvme_msg(link->root, LOG_ERR,
			"nvme_mi_admin_admin_passthru doesn't support data_len over 4096 bytes.\n");
		return -EINVAL;
	}

	if (data != NULL && data_len != 0) {
		if (direction == NVME_DATA_TFR_HOST_TO_CTRL)
			has_write_data = true;
		if (direction == NVME_DATA_TFR_CTRL_TO_HOST)
			has_read_data = true;
	}

	nvme_mi_admin_init_req(link->ep, &req, &req_hdr, link->id, opcode);
	req_hdr.cdw1 = cpu_to_le32(nsid);
	req_hdr.cdw2 = cpu_to_le32(cdw2);
	req_hdr.cdw3 = cpu_to_le32(cdw3);
	req_hdr.cdw10 = cpu_to_le32(cdw10);
	req_hdr.cdw11 = cpu_to_le32(cdw11);
	req_hdr.cdw12 = cpu_to_le32(cdw12);
	req_hdr.cdw13 = cpu_to_le32(cdw13);
	req_hdr.cdw14 = cpu_to_le32(cdw14);
	req_hdr.cdw15 = cpu_to_le32(cdw15);
	req_hdr.doff = 0;
	if (data_len != 0) {
		req_hdr.dlen = cpu_to_le32(data_len);
		/* Bit 0 set to 1 means DLEN contains a value */
		req_hdr.flags = 0x1;
	}

	if (has_write_data) {
		req.data = data;
		req.data_len = data_len;
	}

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	if (has_read_data) {
		resp.data = data;
		resp.data_len = data_len;
	}

	/* if the user has specified a custom timeout, save the current
	 * timeout and override
	 */
	if (timeout_ms != 0) {
		timeout_save = nvme_mi_ep_get_timeout(link->ep);
		nvme_mi_ep_set_timeout(link->ep, timeout_ms);
	}
	rc = nvme_mi_submit(link->ep, &req, &resp);
	if (timeout_ms != 0)
		nvme_mi_ep_set_timeout(link->ep, timeout_save);

	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, result);
	if (rc)
		return rc;

	if (has_read_data && (resp.data_len != data_len))
		return -EPROTO;

	return 0;
}

int nvme_mi_control(nvme_mi_ep_t ep, __u8 opcode,
		    __u16 cpsp, __u16 *result_cpsr)
{
	struct nvme_mi_control_resp control_resp;
	struct nvme_mi_control_req control_req;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc = 0;

	nvme_mi_control_init_req(ep, &req, &control_req, opcode, cpsp);
	nvme_mi_control_init_resp(&resp, &control_resp);

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_control_parse_status(&resp, result_cpsr);
	if (rc)
		return rc;

	return 0;
}

static void nvme_mi_mi_init_req(nvme_mi_ep_t ep,
	struct nvme_mi_req *req,
	struct nvme_mi_mi_req_hdr *hdr,
	__u32 cdw0, __u8 opcode)
{
	memset(req, 0, sizeof(*req));
	memset(hdr, 0, sizeof(*hdr));

	hdr->hdr.type = NVME_MI_MSGTYPE_NVME;
	hdr->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_MI << 3) |
		(ep->csi & 1);
	hdr->opcode = opcode;
	hdr->cdw0 = cpu_to_le32(cdw0);

	req->hdr = &hdr->hdr;
	req->hdr_len = sizeof(*hdr);
}

static int nvme_mi_read_data(nvme_mi_ep_t ep, __u32 cdw0,
			     void *data, size_t *data_len)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	nvme_mi_mi_init_req(ep, &req, &req_hdr, cdw0,
		nvme_mi_mi_opcode_mi_data_read);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = data;
	resp.data_len = *data_len;

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	*data_len = resp.data_len;

	return 0;
}

int nvme_mi_mi_xfer(nvme_mi_ep_t ep,
		       struct nvme_mi_mi_req_hdr *mi_req,
		       size_t req_data_size,
		       struct nvme_mi_mi_resp_hdr *mi_resp,
		       size_t *resp_data_size)
{
	int rc;
	struct nvme_mi_req req;
	struct nvme_mi_resp resp;

	/* There is nothing in the spec to define this limit but going with the limits
	 * from the admin message types for DLEN seems like a reasonable starting point
	 * to check for coding errors
	 */
	const size_t mi_data_xfer_size_limit = 4096;

	/* length/offset checks. The common _submit() API will do further
	 * checking on the message lengths too, so these are kept specific
	 * to the requirements of the particular command set
	 */

	if (*resp_data_size > mi_data_xfer_size_limit)
		return -EINVAL;

	mi_req->hdr.type = NVME_MI_MSGTYPE_NVME;
	mi_req->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
			  (NVME_MI_MT_MI << 3) |
			  (ep->csi & 1);

	memset(&req, 0, sizeof(req));
	req.hdr = &mi_req->hdr;
	req.hdr_len = sizeof(*mi_req);
	req.data = mi_req + 1;
	req.data_len = req_data_size;

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &mi_resp->hdr;
	resp.hdr_len = sizeof(*mi_resp);
	resp.data = mi_resp + 1;
	resp.data_len = *resp_data_size;

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	*resp_data_size = resp.data_len;

	return 0;
}

int nvme_mi_mi_read_mi_data_subsys(nvme_mi_ep_t ep,
				   struct nvme_mi_read_nvm_ss_info *s)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = (__u8)nvme_mi_dtyp_subsys_info << 24;
	len = sizeof(*s);

	rc = nvme_mi_read_data(ep, cdw0, s, &len);
	if (rc)
		return rc;

	if (len != sizeof(*s)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "MI read data length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 len, sizeof(*s));
		return -EPROTO;
	}

	return 0;
}

int nvme_mi_mi_read_mi_data_port(nvme_mi_ep_t ep, __u8 portid,
				 struct nvme_mi_read_port_info *p)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_port_info << 24) | (portid << 16);
	len = sizeof(*p);

	rc = nvme_mi_read_data(ep, cdw0, p, &len);
	if (rc)
		return rc;

	if (len != sizeof(*p))
		return -EPROTO;

	return 0;
}

int nvme_mi_mi_read_mi_data_ctrl_list(nvme_mi_ep_t ep, __u8 start_ctrlid,
				       struct nvme_ctrl_list *list)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_list << 24) | (start_ctrlid << 16);
	len = sizeof(*list);

	rc = nvme_mi_read_data(ep, cdw0, list, &len);
	if (rc)
		return rc;

	return 0;
}

int nvme_mi_mi_read_mi_data_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id,
				       struct nvme_mi_read_ctrl_info *ctrl)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_info << 24) | cpu_to_le16(ctrl_id);
	len = sizeof(*ctrl);

	rc = nvme_mi_read_data(ep, cdw0, ctrl, &len);
	if (rc)
		return rc;

	if (len != sizeof(*ctrl))
		return -EPROTO;

	return 0;
}

int nvme_mi_mi_subsystem_health_status_poll(nvme_mi_ep_t ep, bool clear,
					    struct nvme_mi_nvm_ss_health_status *sshs)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	nvme_mi_mi_init_req(ep, &req, &req_hdr, 0,
		nvme_mi_mi_opcode_subsys_health_status_poll);
	req_hdr.cdw1 = (clear ? 1 : 0) << 31;

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = sshs;
	resp.data_len = sizeof(*sshs);

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	if (resp.data_len != sizeof(*sshs)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "MI Subsystem Health Status length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 resp.data_len, sizeof(*sshs));
		return -EPROTO;
	}

	return 0;
}

int nvme_mi_mi_config_set_get_ex(nvme_mi_ep_t ep, __u8 opcode, __u32 dw0,
				__u32 dw1, void *data_out, size_t data_out_len,
				void *data_in, size_t *data_in_len, __u32 *nmresp)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	nvme_mi_mi_init_req(ep, &req, &req_hdr, dw0, opcode);
	req_hdr.cdw1 = cpu_to_le32(dw1);
	req.data = data_out;
	req.data_len = data_out_len;

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = data_in;
	resp.data_len = *data_in_len;

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	*data_in_len = resp.data_len;

	if (nmresp) {
		*nmresp = resp_hdr.nmresp[0] |
		resp_hdr.nmresp[1] << 8 |
		resp_hdr.nmresp[2] << 16;
	}

	return 0;
}

int nvme_mi_mi_config_get(nvme_mi_ep_t ep, __u32 dw0, __u32 dw1,
			  __u32 *nmresp)
{
	size_t data_in_len = 0;

	return nvme_mi_mi_config_set_get_ex(ep,
					nvme_mi_mi_opcode_configuration_get,
					dw0,
					dw1,
					NULL,
					0,
					NULL,
					&data_in_len,
					nmresp);
}

int nvme_mi_mi_config_set(nvme_mi_ep_t ep, __u32 dw0, __u32 dw1)
{
	size_t data_in_len = 0;

	return nvme_mi_mi_config_set_get_ex(ep,
					nvme_mi_mi_opcode_configuration_set,
					dw0,
					dw1,
					NULL,
					0,
					NULL,
					&data_in_len,
					NULL);
}

int nvme_mi_mi_config_get_async_event(nvme_mi_ep_t ep,
				__u8 *aeelver,
				struct nvme_mi_aem_supported_list *list,
				size_t *list_num_bytes)
{

	__u32 dw0 = NVME_MI_CONFIG_AE;
	__u32 aeelvertemp = 0;

	int rc = nvme_mi_mi_config_set_get_ex(ep,
					nvme_mi_mi_opcode_configuration_get,
					dw0,
					0,
					NULL,
					0,
					list,
					list_num_bytes,
					&aeelvertemp);

	if (rc)
		return rc;

	*aeelver = 0x000F & aeelvertemp;

	return 0;
}

int nvme_mi_mi_config_set_async_event(nvme_mi_ep_t ep,
				bool envfa,
				bool empfa,
				bool encfa,
				__u8 aemd,
				__u8 aerd,
				struct nvme_mi_aem_enable_list *enable_list,
				size_t enable_list_size,
				struct nvme_mi_aem_occ_list_hdr *occ_list,
				size_t *occ_list_size)
{

	__u32 dw0 = ((__u32)envfa << 26) |
				((__u32)empfa << 25) |
				((__u32)encfa << 24) |
				((__u32)aemd << 16)  |
				((__u16) aerd << 8)  | NVME_MI_CONFIG_AE;

	// Basic checks here on lengths
	if (enable_list_size < sizeof(struct nvme_mi_aem_enable_list) ||
	    (sizeof(struct nvme_mi_aem_enable_list) +
	     enable_list->hdr.numaee * sizeof(struct nvme_mi_aem_enable_item)
	     > enable_list_size))
		return -EINVAL;

	// Some very baseic header checks
	if (enable_list->hdr.aeelhl != sizeof(struct nvme_mi_aem_enable_list_header) ||
	    enable_list->hdr.aeelver != 0)
		return -EINVAL;

	return nvme_mi_mi_config_set_get_ex(ep,
		nvme_mi_mi_opcode_configuration_set,
		dw0,
		0,
		enable_list,
		enable_list_size,
		occ_list,
		occ_list_size,
		NULL);
}


void nvme_mi_close(nvme_mi_ep_t ep)
{
	struct nvme_link *link, *tmp;

	/* don't look for controllers during destruction */
	ep->controllers_scanned = true;

	nvme_mi_for_each_link_safe(ep, link, tmp)
		nvme_close(link);

	if (ep->transport && ep->transport->close)
		ep->transport->close(ep);
	list_del(&ep->root_entry);
	free(ep);
}

char *nvme_mi_endpoint_desc(nvme_mi_ep_t ep)
{
	char tsbuf[101], *s = NULL;
	size_t tslen;
	int rc;

	rc = -1;
	memset(tsbuf, 0, sizeof(tsbuf));
	if (ep->transport->desc_ep)
		rc = ep->transport->desc_ep(ep, tsbuf, sizeof(tsbuf) - 1);

	if (!rc) {
		/* don't overflow if the transport gives us an invalid string */
		tsbuf[sizeof(tsbuf)-1] = '\0';
		tslen = strlen(tsbuf);
	} else {
		tslen = 0;
	}

	if (tslen)
		rc = asprintf(&s, "%s: %s", ep->transport->name, tsbuf);
	else
		rc = asprintf(&s, "%s endpoint", ep->transport->name);

	if (rc < 0)
		return NULL;

	return s;
}

nvme_mi_ep_t nvme_mi_first_endpoint(nvme_root_t m)
{
	return list_top(&m->endpoints, struct nvme_mi_ep, root_entry);
}

nvme_mi_ep_t nvme_mi_next_endpoint(nvme_root_t m, nvme_mi_ep_t ep)
{
	return ep ? list_next(&m->endpoints, ep, root_entry) : NULL;
}

nvme_link_t nvme_mi_first_link(nvme_mi_ep_t ep)
{
	return list_top(&ep->controllers, struct nvme_link, ep_entry);
}

nvme_link_t nvme_mi_next_link(nvme_mi_ep_t ep, nvme_link_t l)
{
	return l ? list_next(&ep->controllers, l, ep_entry) : NULL;
}

static const char *const mi_status[] = {
        [NVME_MI_RESP_MPR]                   = "More Processing Required: The command message is in progress and requires more time to complete processing",
        [NVME_MI_RESP_INTERNAL_ERR]          = "Internal Error: The request message could not be processed due to a vendor-specific error",
        [NVME_MI_RESP_INVALID_OPCODE]        = "Invalid Command Opcode",
        [NVME_MI_RESP_INVALID_PARAM]         = "Invalid Parameter",
        [NVME_MI_RESP_INVALID_CMD_SIZE]      = "Invalid Command Size: The size of the message body of the request was different than expected",
        [NVME_MI_RESP_INVALID_INPUT_SIZE]    = "Invalid Command Input Data Size: The command requires data and contains too much or too little data",
        [NVME_MI_RESP_ACCESS_DENIED]         = "Access Denied. Processing prohibited due to a vendor-specific mechanism of the Command and Feature lockdown function",
        [NVME_MI_RESP_VPD_UPDATES_EXCEEDED]  = "VPD Updates Exceeded",
        [NVME_MI_RESP_PCIE_INACCESSIBLE]     = "PCIe Inaccessible. The PCIe functionality is not available at this time",
        [NVME_MI_RESP_MEB_SANITIZED]         = "Management Endpoint Buffer Cleared Due to Sanitize",
        [NVME_MI_RESP_ENC_SERV_FAILURE]      = "Enclosure Services Failure",
        [NVME_MI_RESP_ENC_SERV_XFER_FAILURE] = "Enclosure Services Transfer Failure: Communication with the Enclosure Services Process has failed",
        [NVME_MI_RESP_ENC_FAILURE]           = "An unrecoverable enclosure failure has been detected by the Enclosuer Services Process",
        [NVME_MI_RESP_ENC_XFER_REFUSED]      = "Enclosure Services Transfer Refused: The NVM Subsystem or Enclosure Services Process indicated an error or an invalid format in communication",
        [NVME_MI_RESP_ENC_FUNC_UNSUP]        = "Unsupported Enclosure Function: An SES Send command has been attempted to a simple Subenclosure",
        [NVME_MI_RESP_ENC_SERV_UNAVAIL]      = "Enclosure Services Unavailable: The NVM Subsystem or Enclosure Services Process has encountered an error but may become available again",
        [NVME_MI_RESP_ENC_DEGRADED]          = "Enclosure Degraded: A noncritical failure has been detected by the Enclosure Services Process",
        [NVME_MI_RESP_SANITIZE_IN_PROGRESS]  = "Sanitize In Progress: The requested command is prohibited while a sanitize operation is in progress",
};

/* kept in mi.c while we have a split libnvme/libnvme-mi; consider moving
 * to utils.c (with nvme_status_to_string) if we ever merge. */
const char *nvme_mi_status_to_string(int status)
{
	const char *s = "Unknown status";

	if (status < ARRAY_SIZE(mi_status) && mi_status[status])
                s = mi_status[status];

        return s;
}

bool nvme_mi_aem_aeei_get_aee(__le16 aeei)
{
	return !!(le16_to_cpu(aeei) & 0x8000);
}

__u8 nvme_mi_aem_aeei_get_aeeid(__le16 aeei)
{
	return (le16_to_cpu(aeei) & 0xFF);
}

void nvme_mi_aem_aeei_set_aeeid(struct nvme_mi_aem_enable_item *item, __u8 aeeid)
{
	__u16 temp = le16_to_cpu(item->aeei);

	item->aeei = cpu_to_le16((temp & 0xFF00) | aeeid);
}

void nvme_mi_aem_aeei_set_aee(struct nvme_mi_aem_enable_item *item, bool enabled)
{
	__u16 temp = le16_to_cpu(item->aeei);
	__u8 bit = (enabled) ? 1 : 0;

	item->aeei = cpu_to_le16((temp & 0xFF) | (bit << 15));
}

bool nvme_mi_aem_aesi_get_aese(__le16 aesi)
{
	return !!(le16_to_cpu(aesi) & 0x8000);
}

__u8 nvme_mi_aem_aesi_get_aesid(__le16 aesi)
{
	return le16_to_cpu(aesi) & 0xff;
}

void nvme_mi_aem_aesi_set_aesid(struct nvme_mi_aem_supported_item *item, __u8 aesid)
{
	__u16 temp = le16_to_cpu(item->aesi);

	item->aesi = cpu_to_le16((temp & 0xFF00) | aesid);
}

void nvme_mi_aem_aesi_set_aee(struct nvme_mi_aem_supported_item *item, bool enabled)
{
	__u16 temp = le16_to_cpu(item->aesi);
	__u8 bit = (enabled) ? 1 : 0;

	item->aesi = cpu_to_le16((temp & 0xFF) | (bit << 15));
}

__u8 nvme_mi_aem_aemti_get_aemgn(__u8 aemti)
{
	return aemti >> 3 & 0x1f;
}

__u32 nvme_mi_aem_aeolli_get_aeoltl(__u8 *aeolli)
{
	//First 23-bits contain the aeoltl
	__u32 aeoltl = aeolli[0] | (aeolli[1] << 8) | (aeolli[2] << 16);

	return aeoltl & 0x7FFFFF;
}

void nvme_mi_aem_aeolli_set_aeoltl(struct nvme_mi_aem_occ_list_hdr *hdr, __u32 aeoltl)
{
	hdr->aeolli[0] = aeoltl & 0xFF;
	hdr->aeolli[1] = (aeoltl >> 8) & 0xFF;
	hdr->aeolli[2] = (hdr->aeolli[2] & 0b10000000) | ((aeoltl >> 16) & 0x7F);
}

static int validate_enabled_list(struct nvme_mi_aem_supported_list *list, size_t len)
{
	if (list->hdr.aeslver != 0)
		return -EPROTO;
	if (list->hdr.aeslhl != sizeof(struct nvme_mi_aem_supported_list))
		return -EPROTO;
	if (list->hdr.aest > len ||
		list->hdr.aest !=
		list->hdr.aeslhl + list->hdr.numaes * sizeof(struct nvme_mi_aem_supported_item)) {
		return -EPROTO;
	}
	return 0;
}
static int validate_occ_list_update_ctx(
							struct nvme_mi_aem_occ_list_hdr *occ_header,
							size_t len,
							struct nvme_mi_aem_ctx *ctx,
							bool check_generation_num)
{
	int err;

	//Make sure header fields have valid data
	if (len < sizeof(*occ_header)) {
		err = -EPROTO;
		goto err_cleanup;
	} else if (occ_header->aelver != 0 ||
			   occ_header->aeolhl != sizeof(*occ_header)) {
		//Make sure header is the right version and length
		err = -EPROTO;
		goto err_cleanup;
	} else if (nvme_mi_aem_aeolli_get_aeoltl(occ_header->aeolli) > len) {
		//Full length is bigger than the data that was received
		err = -EPROTO;
		goto err_cleanup;
	} else if (check_generation_num &&
		ctx->last_generation_num ==
			(int) nvme_mi_aem_aemti_get_aemgn(occ_header->aemti)) {
		//This is a duplicate and shouldn't be parsed.
		//Let's just act like there's no updates
		occ_header->numaeo = 0;
	} else if (check_generation_num) {
		ctx->last_generation_num =
			nvme_mi_aem_aemti_get_aemgn(occ_header->aemti);
	}

	//Header is fine.  Let's go through the data
	//First, we should update our context appropriately
	ctx->occ_header = occ_header;

	//Data starts after header
	ctx->list_current = (struct nvme_mi_aem_occ_data *) (occ_header + 1);
	ctx->list_current_index = 0;
	ctx->list_start = ctx->list_current;

	struct nvme_mi_aem_occ_data *current = ctx->list_current;
	size_t bytes_so_far = ctx->occ_header->aeolhl;

	for (int i = 0; i < occ_header->numaeo; i++) {
		//Validate this item
		if (current->aelhlen != sizeof(*current)) {
			err = -EPROTO;
			goto err_cleanup;
		} else if (!ctx->callbacks.enabled_map.enabled[current->aeoui.aeoi]) {
			//This is unexpected as this AE shouldn't be enabled
			err = -EPROTO;
			goto err_cleanup;
		}

		//Okay, check data lengths, including this header and the specific data(s)
		uint32_t offset = sizeof(*current) + current->aeosil + current->aeovsil;

		bytes_so_far += offset;
		if (bytes_so_far > nvme_mi_aem_aeolli_get_aeoltl(occ_header->aeolli)) {
			err = -EPROTO;
			goto err_cleanup;
		}

		current = (struct nvme_mi_aem_occ_data *)((uint8_t *)current + offset);
	}

	return 0;

err_cleanup:
	return err;
}

int nvme_mi_aem_get_fd(nvme_mi_ep_t ep)
{
	if (!ep || !ep->aem_ctx || !ep->transport || !ep->transport->aem_fd)
		return -1;

	return ep->transport->aem_fd(ep);
}

static void reset_list_info(struct nvme_mi_aem_ctx *ctx)
{
	//Reset context information
	ctx->list_current_index = -1;
	ctx->list_start = NULL;
	ctx->list_current = NULL;
	ctx->occ_header = NULL;
}

static int aem_sync(nvme_mi_ep_t ep,
	bool envfa,
	bool empfa,
	bool encfa,
	__u8 aemd,
	__u8 aerd,
	struct nvme_mi_aem_enable_item *items,
	__u8 num_items,
	struct nvme_mi_aem_occ_list_hdr *resp,
	size_t *resp_len
)
{
	size_t msg_len =
		sizeof(struct nvme_mi_aem_enable_list_header) +
		num_items * sizeof(struct nvme_mi_aem_enable_item);

	struct nvme_mi_aem_enable_list_header *request = malloc(msg_len);

	if (!request)
		return -1;

	request->aeelhl = sizeof(struct nvme_mi_aem_enable_list_header);
	request->numaee = num_items;
	request->aeelver = 0;
	request->aeetl = msg_len;

	//Data follows header
	struct nvme_mi_aem_enable_item *msg_items = (struct nvme_mi_aem_enable_item *)(request + 1);

	//Let's be explicit about what's enabled and what's not
	for (int i = 0; i < num_items; i++) {
		msg_items[i] = items[i];
		msg_items[i].aeel = sizeof(msg_items[i]);
	}

	//Send it
	int rc = nvme_mi_mi_config_set_async_event(ep,
					envfa,
					empfa,
					encfa,
					aemd,
					aerd,
					(struct nvme_mi_aem_enable_list *)request,
					msg_len,
					resp,
					resp_len);

	free(request);
	return rc;
}

static int aem_disable_enabled(nvme_mi_ep_t ep)
{
	struct nvme_mi_aem_enabled_map already_enabled = {false};
	uint8_t response_buffer[4096] = {0};
	size_t response_len = sizeof(response_buffer);
	struct nvme_mi_aem_occ_list_hdr *response =
		(struct nvme_mi_aem_occ_list_hdr *)response_buffer;

	// First, let's figure out if anything is already enabled that we need to
    // disable
	int rc = nvme_mi_aem_get_enabled(ep, &already_enabled);

	if (rc)
		return rc;

	int sync_data_count = 0;

	//Add the enabled items to the list of things to disable
	struct nvme_mi_aem_enable_item sync_data[NUM_ENABLES] = {0};

	for (int i = 0; i < NUM_ENABLES; i++) {
		if (already_enabled.enabled[i]) {
			nvme_mi_aem_aeei_set_aeeid(&sync_data[sync_data_count], i);
			nvme_mi_aem_aeei_set_aee(&sync_data[sync_data_count], false);
			sync_data_count++;
		}
	}

	rc = aem_sync(ep, false, false, false, 1, 0,
		sync_data, sync_data_count, response, &response_len);

	if (rc)
		return rc;

	//Now, allow a purge of the aem fd because we could have
	//received some events during this process
	rc = ep->transport->aem_purge(ep);

	return rc;
}

int nvme_mi_aem_enable(nvme_mi_ep_t ep,
	struct nvme_mi_aem_config *config,
	void *userdata)
{
	if (!ep || !config || !config->aem_handler)
		return -1;

	int rc = nvme_mi_aem_open(ep);

	if (rc < 0)
		return rc;

	int sync_data_count = 0;
	struct nvme_mi_aem_enable_item sync_data[NUM_ENABLES] = {0};

	uint8_t response_buffer[4096] = {0};
	size_t response_len = sizeof(response_buffer);
	struct nvme_mi_aem_occ_list_hdr *response =
		(struct nvme_mi_aem_occ_list_hdr *)response_buffer;

	//It's possible we're already enabled
	if (!ep->aem_ctx)
		ep->aem_ctx = malloc(sizeof(*ep->aem_ctx));
	if (!(ep->aem_ctx))
		return -1;

	memset(ep->aem_ctx, 0, sizeof(*ep->aem_ctx));
	ep->aem_ctx->last_generation_num = -1;//Invalid
	reset_list_info((ep->aem_ctx));
	ep->aem_ctx->callbacks = *config;

	rc = aem_disable_enabled(ep);
	if (rc)
		goto cleanup_ctx;

	//Now, let's do a fresh enable of what's asked
	for (int i = 0; i < NUM_ENABLES; i++) {
		if (config->enabled_map.enabled[i]) {
			nvme_mi_aem_aeei_set_aeeid(&sync_data[sync_data_count], i);
			nvme_mi_aem_aeei_set_aee(&sync_data[sync_data_count], true);
			sync_data_count++;
		}
	}

	rc = aem_sync(ep, config->envfa, config->empfa,
		config->encfa, config->aemd, config->aerd,
		sync_data, sync_data_count, response, &response_len);
	if (rc)
		goto cleanup_ctx;

	//Parse the response and fire events
	rc = validate_occ_list_update_ctx(response,
					response_len,
					ep->aem_ctx,
					false /*generation # shouldn't matter*/);
	if (rc)
		goto cleanup_ctx;

	if (response->numaeo) {
		//Return value unused here
		config->aem_handler(ep, response->numaeo, userdata);
	}

cleanup_ctx:
	// Clear these because they won't point to valid memory anymore
	reset_list_info(ep->aem_ctx);

	if (rc) {
		free(ep->aem_ctx);
		ep->aem_ctx = NULL;
	}
	return rc;
}

int nvme_mi_aem_get_enabled(nvme_mi_ep_t ep,
	struct nvme_mi_aem_enabled_map *enabled_map)
{
	if (!ep || !enabled_map)
		return -1;

	int rc = 0;

	unsigned char aeelver;
	size_t ae_list_bytes = NUM_ENABLES * sizeof(struct nvme_mi_aem_supported_list);
	struct nvme_mi_aem_supported_list *enabled_list = malloc(ae_list_bytes);

	if (!enabled_list)
		return -1;

	rc = nvme_mi_mi_config_get_async_event(
		ep, &aeelver, enabled_list, &ae_list_bytes);
	if (rc)
		goto cleanup;

	rc = validate_enabled_list(enabled_list, ae_list_bytes);
	if (rc)
		goto cleanup;

	memset(enabled_map, 0, sizeof(*enabled_map));

	struct nvme_mi_aem_enable_item *items =
		(struct nvme_mi_aem_enable_item *)(enabled_list + 1);

	for (int i = 0; i < enabled_list->hdr.numaes; i++) {
		__u8 aeeid = nvme_mi_aem_aeei_get_aeeid(items[i].aeei);
		bool enabled = nvme_mi_aem_aeei_get_aee(items[i].aeei);

		enabled_map->enabled[aeeid] = enabled;
	}

cleanup:
	free(enabled_list);
	return rc;
}

int nvme_mi_aem_disable(nvme_mi_ep_t ep)
{
	if (!ep)
		return -1;

	int rc = aem_disable_enabled(ep);

	free(ep->aem_ctx);
	ep->aem_ctx = NULL;

	return rc;
}

/*When inside a aem_handler, call with the aem_ctx and struct will be populated with next
 *event information.  Will return NULL when end of parsing (or error) is occurred.
 *spec_info and vend_spec_info must be copied to persist as they will not be valid after
 *the aem_handler has returned.
 */
struct nvme_mi_event *nvme_mi_aem_get_next_event(nvme_mi_ep_t ep)
{
	if (!ep || !ep->aem_ctx ||
		!ep->aem_ctx->list_current ||
		ep->aem_ctx->list_current_index == -1 ||
	    !ep->aem_ctx->occ_header) {
		return NULL;
	}

	if (ep->aem_ctx->occ_header->numaeo <= ep->aem_ctx->list_current_index)
		return NULL;

	struct nvme_mi_aem_ctx *aem_ctx = ep->aem_ctx;
	struct nvme_mi_aem_occ_data *current = aem_ctx->list_current;

	aem_ctx->event.aeoi = current->aeoui.aeoi;
	aem_ctx->event.aessi = current->aeoui.aessi;
	aem_ctx->event.aeocidi = current->aeoui.aeocidi;
	aem_ctx->event.spec_info_len = current->aeosil;
	aem_ctx->event.vend_spec_info_len = current->aeovsil;
	//Now the pointers
	aem_ctx->event.spec_info = ((uint8_t *)current + current->aelhlen);
	aem_ctx->event.vend_spec_info =
		((uint8_t *)aem_ctx->event.spec_info + aem_ctx->event.spec_info_len);

	//Let's grab the next item (if there is any).
	aem_ctx->list_current_index++;
	aem_ctx->list_current =
		(struct nvme_mi_aem_occ_data *)
		((uint8_t *)aem_ctx->event.vend_spec_info + aem_ctx->event.vend_spec_info_len);

	return &aem_ctx->event;
}

/* POLLIN has indicated events.  This function reads and processes them.
 * A callback will likely be invoked.
 */
int nvme_mi_aem_process(nvme_mi_ep_t ep, void *userdata)
{
	int rc = 0;
	uint8_t response_buffer[4096];
	struct nvme_mi_aem_msg *response = (struct nvme_mi_aem_msg *)response_buffer;
	size_t response_len = sizeof(response_buffer) - sizeof(struct nvme_mi_aem_msg);

	if (!ep || !ep->aem_ctx)
		return -1;

	memset(response_buffer, 0, sizeof(response_buffer));

	//Reset context information
	reset_list_info(ep->aem_ctx);

	rc = nvme_mi_get_async_message(ep, response, &response_len);
	if (rc)
		goto cleanup;

	if (!response_len) {
		//If no error and response length zero, we've likely received an owned
		//tag message from a different endpoint than this path is responsible
		//for monitoring.
		goto cleanup;
	}

	//Parse the response and fire events
	rc = validate_occ_list_update_ctx(&response->occ_list_hdr,
						response_len,
						ep->aem_ctx,
						true /*Ensure unique generation number*/);
	if (rc)
		goto cleanup;

	if (response->occ_list_hdr.numaeo) {
		enum nvme_mi_aem_handler_next_action action =
			ep->aem_ctx->callbacks.aem_handler(ep,
								response->occ_list_hdr.numaeo,
								userdata);

		reset_list_info(ep->aem_ctx);

		if (action == NVME_MI_AEM_HNA_ACK) {
			response_len = sizeof(response_buffer);

			rc = nvme_mi_aem_ack(ep, &response->occ_list_hdr, &response_len);
			if (rc)
				goto cleanup;

			//The Ack is not guaranteed to have data
			if (response_len && response->occ_list_hdr.numaeo) {
				rc = validate_occ_list_update_ctx(&response->occ_list_hdr,
										response_len,
										ep->aem_ctx,
										true);
				//Callbacks based on ack
				if (rc == 0 && response->occ_list_hdr.numaeo) {
					//Return value unused here
					ep->aem_ctx->callbacks.aem_handler(ep,
							response->occ_list_hdr.numaeo,
							userdata);
				}
			}
		}
	} else {
		//This is unexpected unless we have duplicates.  But those shouldn't be acked
	}

cleanup:
	reset_list_info(ep->aem_ctx);
	return rc;
}


