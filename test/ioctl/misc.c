// SPDX-License-Identifier: LGPL-2.1-or-later

#include <libnvme.h>

#include "mock.h"
#include "util.h"
#include <nvme/api-types.h>
#include <nvme/ioctl.h>
#include <nvme/types.h>
#include <string.h>

#define TEST_FD 0xFD
#define TEST_NSID 0x12345678
#define TEST_CSI NVME_CSI_KV

static nvme_link_t test_link;

static void test_format_nvm(void)
{
	enum nvme_cmd_format_mset mset = NVME_FORMAT_MSET_EXTENDED;
	enum nvme_cmd_format_pi pi = NVME_FORMAT_PI_TYPE2;
	enum nvme_cmd_format_pil pil = NVME_FORMAT_PIL_FIRST;
	enum nvme_cmd_format_ses ses = NVME_FORMAT_SES_USER_DATA_ERASE;
	__u32 nsid = TEST_NSID;
	__u8 lbaf = 0x1F;
	__u32 result = 0;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_format_nvm,
		.nsid = nsid,
		.cdw10 = lbaf | (mset << 4) | (pi << 5) |
			 (pil << 8) | (ses << 9) | ((lbaf >> 4) << 12),
		.result = 0,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_format_nvm(test_link, nsid, lbaf, mset, pi, pil,
			      ses, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_ns_mgmt(void)
{
	struct nvme_ns_mgmt_host_sw_specified expected_data, data = {};
	enum nvme_ns_mgmt_sel sel = NVME_NS_MGMT_SEL_CREATE;
	__u32 nsid = TEST_NSID;
	__u8 csi = TEST_CSI;
	__u32 result = 0;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = nsid,
		.cdw10 = sel,
		.cdw11 = csi << 24,
		.result = 0,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_mgmt(test_link, TEST_NSID, NVME_NS_MGMT_SEL_CREATE,
			   TEST_CSI, &data, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_ns_mgmt_create(void)
{
	struct nvme_ns_mgmt_host_sw_specified expected_data, data = {};
	enum nvme_ns_mgmt_sel sel = NVME_NS_MGMT_SEL_CREATE;
	__u32 nsid = NVME_NSID_NONE;
	__u8 csi = NVME_CSI_ZNS;
	__u32 result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = nsid,
		.cdw10 = sel,
		.cdw11 = csi << 24,
		.result = TEST_NSID,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_mgmt_create(test_link, csi, &data, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == TEST_NSID, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_ns_mgmt_delete(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_MGMT_SEL_DELETE,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_mgmt_delete(test_link, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_get_property(void)
{
	__u64 expected_result, result;
	struct nvme_get_property_args args = {
		.value = &result,
		.args_size = sizeof(args),
		.offset = NVME_REG_ACQ,
	};

	arbitrary(&expected_result, sizeof(expected_result));

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fabrics,
		.nsid = nvme_fabrics_type_property_get,
		.cdw10 = !!true,
		.cdw11 = NVME_REG_ACQ,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_property(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "returned wrong result");
}

static void test_set_property(void)
{
	__u64 value = 0xffffffff;
	__u32 result;
	struct nvme_set_property_args args = {
		.value = value,
		.result = &result,
		.args_size = sizeof(args),
		.offset = NVME_REG_BPMBL,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fabrics,
		.nsid = nvme_fabrics_type_property_set,
		.cdw10 = !!true,
		.cdw11 = NVME_REG_BPMBL,
		.cdw12 = value & 0xffffffff,
		.cdw13 = value >> 32,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_property(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_ns_attach(void)
{
	struct nvme_ctrl_list expected_ctrlist, ctrlist;
	enum nvme_ns_attach_sel sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH;
	__u32 nsid = TEST_NSID;
	__u32 result;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = nsid,
		.cdw10 = sel,
		.data_len = sizeof(expected_ctrlist),
		.out_data = &expected_ctrlist,
	};

	int err;

	arbitrary(&expected_ctrlist, sizeof(expected_ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_attach(test_link, nsid, sel, &ctrlist, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&expected_ctrlist, &ctrlist, sizeof(expected_ctrlist),
	    "incorrect data");
}

static void test_ns_attach_ctrls(void)
{
	struct nvme_ctrl_list ctrlist;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_ATTACH_SEL_CTRL_ATTACH,
		.data_len = sizeof(ctrlist),
		.out_data = &ctrlist,
	};

	int err;

	arbitrary(&ctrlist, sizeof(ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_attach_ctrls(test_link, TEST_NSID, &ctrlist);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_ns_detach_ctrls(void)
{
	struct nvme_ctrl_list ctrlist;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
		.data_len = sizeof(ctrlist),
		.out_data = &ctrlist,
	};

	int err;

	arbitrary(&ctrlist, sizeof(ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_detach_ctrls(test_link, TEST_NSID, &ctrlist);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_fw_download(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(expected_data);
	__u32 offset = 120;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fw_download,
		.cdw10 = (data_len >> 2) - 1,
		.cdw11 = offset >> 2,
		.data_len = data_len,
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_fw_download(test_link, expected_data, data_len, offset, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_fw_commit(void)
{
	enum nvme_fw_commit_ca action = NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE;
	__u32 result = 0;
	__u8 slot = 0xf;
	bool bpid = true;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fw_commit,
		.cdw10 = (!!bpid << 31) | (action << 3) | slot,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_fw_commit(test_link, slot, action, bpid, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_security_send(void)
{
	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(expected_data);
	__u32 nsid = TEST_NSID;
	__u32 tl = 0xffff;
	__u32 result = 0;
	__u8 nssf = 0x1; 
	__u16 spsp = 0x0101;
	__u8 secp = 0xE9;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_send,
		.nsid = TEST_NSID,
		.cdw10 = nssf | (spsp << 8) | (secp << 24),
		.cdw11 = tl,
		.data_len = data_len,
		.in_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_security_send(test_link, nsid, nssf, spsp, secp, tl,
				 &expected_data, data_len, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_security_receive(void)
{
	__u8 expected_data[8], data[8];
	__u32 result = 0;
	__u32 al = 0xffff;
	__u8 spsp0 = 0x1;
	__u8 spsp1 = 0x1;
	__u8 secp = 0xE9;
	__u8 nssf = 0x1;
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_recv,
		.nsid = TEST_NSID,
		.cdw10 = nssf | (spsp0 << 8) | (spsp1 << 16) | (secp << 24),
		.cdw11 = al,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_security_receive(test_link, TEST_NSID, nssf, spsp0, spsp1,
				    secp, al, &data, sizeof(data), &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_get_lba_status(void)
{
	__u8 nlsd = 3;
	int lba_status_size = sizeof(struct nvme_lba_status) +
			      nlsd * sizeof(struct nvme_lba_status_desc);
	enum nvme_lba_status_atype atype = 0x11;
	__u32 mndw = (lba_status_size - 1) >> 2;
	__u64 slba = 0x123456789;
	__u32 result = 0;
	__u16 rl = 0x42;
	int err;

	_cleanup_free_ struct nvme_lba_status *lbas = NULL;
	_cleanup_free_ struct nvme_lba_status *expected_lbas = NULL;

	lbas = malloc(lba_status_size);
	check(lbas, "lbas: ENOMEM");
	expected_lbas = malloc(lba_status_size);
	check(expected_lbas, "expected_lbas: ENOMEM");

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_lba_status,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = mndw,
		.cdw13 = rl | (atype << 24),
		.data_len = (mndw + 1) << 2,
		.out_data = expected_lbas,
	};

	arbitrary(expected_lbas, lba_status_size);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_lba_status(test_link, TEST_NSID, slba, mndw, atype,
				  rl, lbas, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned wrong result");
	cmp(lbas, expected_lbas, lba_status_size, "incorrect lbas");
}

static void test_directive_send(void)
{
	enum nvme_directive_send_doper doper = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE;
	enum nvme_directive_dtype dtype = NVME_DIRECTIVE_DTYPE_STREAMS;
	__u8 expected_data[8], data[8];
	__u32 cdw12 = 0xffff;
	__u16 dspec = 0x0;
	__u32 result = 0;
	__u32 data_len = sizeof(expected_data);
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw10 = data_len ? (data_len >> 2) - 1 : 0,
		.cdw11 = doper | (dtype << 8) | (dspec << 16),
		.cdw12 = cdw12,
		.data_len = data_len,
		.in_data = &data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send(test_link, TEST_NSID, doper, dtype, dspec,
				  cdw12, &expected_data,
				  data_len, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_directive_send_id_endir(void)
{
	struct nvme_id_directives expected_id, id;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw10 = (sizeof(expected_id) >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR |
			 (NVME_DIRECTIVE_DTYPE_IDENTIFY << 8),
		.cdw12 = (!!true) | (NVME_DIRECTIVE_DTYPE_STREAMS << 1),
		.data_len = sizeof(id),
		.in_data = &id,
	};

	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	memcpy(&id, &expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send_id_endir(test_link, TEST_NSID, true,
					   NVME_DIRECTIVE_DTYPE_STREAMS, &id);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect id");
}

static void test_directive_send_stream_release_identifier(void)
{
	__u16 stream_id = 0x1234;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8) |
			 (stream_id << 16),
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send_stream_release_identifier(test_link, TEST_NSID,
							    stream_id);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_directive_send_stream_release_resource(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send_stream_release_resource(test_link, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_directive_recv(void)
{
	enum nvme_directive_receive_doper doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM;
	enum nvme_directive_dtype dtype = NVME_DIRECTIVE_DTYPE_STREAMS;
	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(data);
	__u32 cdw12 = 0xffff;
	__u16 dspec = 0x0;
	__u32 result = 0;
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = data_len ? (data_len >> 2) - 1 : 0,
		.cdw11 = doper | (dtype << 8) | (dspec << 16),
		.cdw12 = cdw12,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv(test_link, TEST_NSID, doper, dtype,
				  dspec, cdw12, &data, data_len,
				  &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_directive_recv_identify_parameters(void)
{
	struct nvme_id_directives expected_id, id;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = (sizeof(expected_id) >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM |
			 (NVME_DIRECTIVE_DTYPE_IDENTIFY << 8),
		.data_len = sizeof(expected_id),
		.out_data = &expected_id,
	};

	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_identify_parameters(test_link, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect id");
}

static void test_directive_recv_stream_parameters(void)
{
	struct nvme_streams_directive_params expected_params, params;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = (sizeof(expected_params) >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
		.data_len = sizeof(expected_params),
		.out_data = &expected_params,
	};

	int err;

	arbitrary(&expected_params, sizeof(expected_params));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_stream_parameters(test_link, TEST_NSID,
						    &params);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&params, &expected_params, sizeof(params), "incorrect params");
}

static void test_directive_recv_stream_status(void)
{
	__u8 nr_entries = 3;
	uint32_t stream_status_size =
		sizeof(struct nvme_streams_directive_status) +
		nr_entries * sizeof(__le16);

	_cleanup_free_ struct nvme_streams_directive_status *expected_status =
		NULL;
	_cleanup_free_ struct nvme_streams_directive_status *status = NULL;

	status = malloc(stream_status_size);
	check(status, "status: ENOMEM");
	expected_status = malloc(stream_status_size);
	check(expected_status, "expected_status: ENOMEM");

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = (stream_status_size >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
		.data_len = stream_status_size,
		.out_data = expected_status,
	};

	int err;

	arbitrary(expected_status, stream_status_size);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_stream_status(test_link, TEST_NSID, nr_entries,
						status);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(status, expected_status, stream_status_size, "incorrect status");
}

static void test_directive_recv_stream_allocate(void)
{
	__u32 expected_result = 0x45, result = 0;
	__u16 nsr = 0x67;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
		.cdw12 = nsr,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_stream_allocate(test_link, TEST_NSID, nsr,
						  &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_capacity_mgmt(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_capacity_mgmt_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.cdw11 = 0x1234,
		.cdw12 = 0x5678,
		.element_id = 0x12,
		.op = 0x3,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_capacity_mgmt,
		.nsid = NVME_NSID_NONE,
		.cdw10 = args.op | args.element_id << 16,
		.cdw11 = args.cdw11,
		.cdw12 = args.cdw12,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_capacity_mgmt(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_lockdown(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_lockdown_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.scp = 0x2,
		.prhbt = !!true,
		.ifc = 0x1,
		.ofi = 0x12,
		.uuidx = 0x34,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_lockdown,
		.cdw10 = args.ofi << 8 | (args.ifc & 0x3) << 5 |
			 (args.prhbt & 0x1) << 4 | (args.scp & 0xF),
		.cdw14 = args.uuidx & 0x3F,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lockdown(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_sanitize_nvm(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_sanitize_nvm_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.sanact = NVME_SANITIZE_SANACT_START_CRYPTO_ERASE,
		.ovrpat = 0x101010,
		.ause = true,
		.owpass = 0x2,
		.oipbp = false,
		.nodas = true,
		.emvs = false,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_sanitize_nvm,
		.cdw10 = args.sanact | (!!args.ause << 3) | (args.owpass << 4) |
			 (!!args.oipbp << 8) | (!!args.nodas << 9),
		.cdw11 = args.ovrpat,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_sanitize_nvm(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_dev_self_test(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_dev_self_test_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.nsid = TEST_NSID,
		.stc = NVME_DST_STC_ABORT,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_dev_self_test,
		.nsid = args.nsid,
		.cdw10 = args.stc,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_dev_self_test(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_virtual_mgmt(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_virtual_mgmt_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.act = NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL,
		.rt = NVME_VIRT_MGMT_RT_VI_RESOURCE,
		.cntlid = 0x0,
		.nr = 0xff,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_virtual_mgmt,
		.cdw10 = args.act | (args.rt << 8) | (args.cntlid << 16),
		.cdw11 = args.nr,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_virtual_mgmt(test_link, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_flush(void)
{
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_flush,
		.nsid = TEST_NSID,
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_flush(test_link, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_read(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;
	__u64 slba = 0xffffffffff;
	__u16 nlb = 0x3;
	__u16 control = NVME_IO_FUA;
	__u8 dsm = NVME_IO_DSM_LATENCY_LOW;
	__u16 apptag = 0x12;
	__u16 appmask = 0x34;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_read,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm,
		.cdw15 = apptag | (appmask << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_read(test_link, TEST_NSID, slba,
			nlb, control, dsm, 0,
			false, 0, 0, 0, 0,
			apptag, appmask,
			&data, sizeof(data),
			NULL, 0,
			&result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_write(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;
	__u64 slba = 0xfffffffabcde;
	__u16 nlb = 0x5;
	__u16 control = NVME_IO_FUA;
	__u8 dsm = NVME_IO_DSM_COMPRESSED;
	__u16 dspec = 0xa;
	__u16 apptag = 0x59;
	__u16 appmask = 0x94;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm | (dspec << 16),
		.cdw15 = apptag | (appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_write(test_link, TEST_NSID, slba,
			 nlb, control,
			 dspec, dsm, 0,
			 false, 0, 0, 0, 0,
			 apptag, appmask,
			 &expected_data, sizeof(expected_data),
			 NULL, 0,
			 &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_compare(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;
	__u64 slba = 0xabcde;
	__u16 nlb = 0x0;
	__u16 control = NVME_IO_LR;
	__u16 cev = 0;
	__u16 apptag = 0x59;
	__u16 appmask = 0x94;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_compare,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = cev,
		.cdw15 = apptag | (appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_compare(test_link, TEST_NSID, slba,
			   nlb, control,
			   0,
			   false, 0, 0, 0, 0,
			   apptag, appmask,
			   &expected_data, sizeof(expected_data),
			   NULL, 0,
			   &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_write_zeros(void)
{
	__u32 result = 0;
	__u64 slba = 0x0;
	__u16 nlb = 0xffff;
	__u16 control = NVME_IO_LR;
	__u8 dsm = NVME_IO_DSM_FREQ_ONCE;
	__u16 cev = 0;
	__u16 dspec = 0xbb;
	__u16 apptag = 0xfa;
	__u16 appmask = 0x72;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write_zeroes,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm | (dspec << 16),
		.cdw15 = apptag | (appmask << 16),
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_write_zeros(test_link, TEST_NSID, slba,
			       nlb, control,
			       dspec, dsm, cev,
			       false, 0, 0, 0, 0,
			       apptag, appmask,
			       &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_write_uncorrectable(void)
{
	__u32 result = 0;
	__u64 slba = 0x0;
	__u16 nlb = 0x0;
	__u16 control = 0x0;
	__u8 dsm = 0x0;
	__u16 dspec = 0x0;
	__u16 apptag = 0x0;
	__u16 appmask = 0x0;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write_uncor,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm | (dspec << 16),
		.cdw15 = apptag | (appmask << 16),
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_write_uncorrectable(test_link, TEST_NSID, slba,
				       nlb, control,
				       0,
				       NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_verify(void)
{
	__u32 result = 0;
	__u64 slba = 0xffffffffffffffff;
	__u16 nlb = 0xffff;
	__u16 control = 0xffff;
	__u16 cev = 0;
	__u16 apptag = 0xffff;
	__u16 appmask = 0xffff;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_verify,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = cev,
		.cdw15 = apptag | (appmask << 16),
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_verify(test_link, TEST_NSID, slba,
			  nlb, control,
			  cev,
			  false, 0, 0, 0, 0,
			  apptag, appmask,
			  &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_dsm(void)
{
	__u32 result = 0;
	__u16 nr_ranges = 0xab;
	int dsm_size = sizeof(struct nvme_dsm_range) * nr_ranges;

	_cleanup_free_ struct nvme_dsm_range *dsm = NULL;

	dsm = malloc(dsm_size);
	check(dsm, "dsm: ENOMEM");

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_dsm,
		.nsid = TEST_NSID,
		.cdw10 = nr_ranges - 1,
		.cdw11 = NVME_DSMGMT_AD,
		.data_len = dsm_size,
		.in_data = dsm,
	};

	int err;

	arbitrary(dsm, dsm_size);
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_dsm(test_link, TEST_NSID, nr_ranges, NVME_DSMGMT_AD, dsm, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_copy(void)
{
	__u16 nr = 0x12, cev = 0, dspec = 0, lbat = 0, lbatm = 0;
	int copy_size = sizeof(struct nvme_copy_range) * nr, err;
	bool prinfor = false, prinfow = false, stcw = false,
		stcr = false, fua = false, lr = false,
		elbas = false;
	__u8 cetype = 0, dtype = 0, desfmt = 0xf, sts = 0, pif = 0;
	__u64 sdlba = 0xfffff, storage_tag = 0;
	__u32 reftag = 0, result = 0;

	_cleanup_free_ struct nvme_copy_range *copy = NULL;

	copy = malloc(copy_size);
	check(copy, "copy: ENOMEM");

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_copy,
		.nsid = TEST_NSID,
		.cdw10 = sdlba & 0xffffffff,
		.cdw11 = sdlba >> 32,
		.cdw12 = ((nr - 1) & 0xff) | ((desfmt & 0xf) << 8) |
			 ((prinfor & 0xf) << 12) |
			 ((dtype & 0xf) << 20) |
			 ((prinfow & 0xf) << 26) |
			 ((fua & 0x1) << 30) | ((lr & 0x1) << 31),
		.data_len = nr * sizeof(struct nvme_copy_range),
		.in_data = copy,
	};

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_copy(test_link, TEST_NSID, sdlba, nr, desfmt,
			prinfor, prinfow, cetype, dtype, stcw, stcr,
			fua, lr, cev, dspec,
			elbas, sts, pif, storage_tag, reftag,
			lbat, lbatm,
			(void *)copy,
			&result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_acquire(void)
{
	enum nvme_resv_rtype rtype = NVME_RESERVATION_RTYPE_EAAR;
	enum nvme_resv_racqa racqa = NVME_RESERVATION_RACQA_PREEMPT;
	__le64 payload[2] = { 0 };
	bool iekey = true;
	__u32 result = 0;
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_acquire,
		.nsid = TEST_NSID,
		.cdw10 = (racqa & 0x7) | (iekey ? 1 << 3 : 0) | (rtype << 8),
		.data_len = sizeof(payload),
		.in_data = payload,
	};

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_acquire(test_link, TEST_NSID, racqa, iekey,
				false, rtype, 0, 0, 0, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_register(void)
{
	enum nvme_resv_rrega rrega = NVME_RESERVATION_RREGA_UNREGISTER_KEY;
	enum nvme_resv_cptpl cptpl = NVME_RESERVATION_CPTPL_PERSIST;
	__le64 payload[2] = { 0xffffffffffffffff, 0 };
	bool iekey = true;
	__u32 result = 0;
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_register,
		.nsid = TEST_NSID,
		.cdw10 = (rrega & 0x7) | (iekey ? 1 << 3 : 0) | (cptpl << 30),
		.data_len = sizeof(payload),
		.in_data = payload,
	};

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_register(test_link, TEST_NSID, rrega, iekey, false, cptpl,
				 0xffffffffffffffff, 0, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_release(void)
{
	enum nvme_resv_rtype rtype = NVME_RESERVATION_RTYPE_WE;
	enum nvme_resv_rrela rrela = NVME_RESERVATION_RRELA_RELEASE;
	__le64 payload[1] = { 0xffffffffffffffff };
	bool iekey = true;
	__u32 result = 0;
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_release,
		.nsid = TEST_NSID,
		.cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) | (rtype << 8),
		.data_len = sizeof(payload),
		.in_data = payload,
	};


	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_release(test_link, TEST_NSID, rrela, 0xffffffffffffffff,
				iekey, false, rtype,  &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_report(void)
{
	struct nvme_resv_status expected_status, status = {};
	__u32 len = sizeof(status);
	__u32 result = 0;
	bool eds = false;
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_report,
		.nsid = TEST_NSID,
		.cdw10 = (len >> 2) - 1,
		.cdw11 = eds ? 1 : 0,
		.data_len = len,
		.out_data = &expected_status,
	};

	arbitrary(&expected_status, sizeof(expected_status));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_report(test_link, TEST_NSID, eds, &status, len, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&status, &expected_status, sizeof(status), "incorrect status");
}

static void test_io_mgmt_recv(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	__u16 mos = 0x1;
	__u8 mo = 0x2;
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = mo | (mos << 16),
		.cdw11 = (data_len >> 2) - 1,
		.data_len = data_len,
		.out_data = &expected_data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_io_mgmt_recv(test_link, TEST_NSID, mo, mos, &data, data_len, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_io_mgmt_send(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(expected_data);
	__u16 mos = 0x1;
	__u8 mo = 0x2;
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = mo | (mos << 16),
		.data_len = data_len,
		.in_data = &data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_io_mgmt_send(test_link, TEST_NSID, mo, mos,
				&expected_data, data_len, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_fdp_reclaim_unit_handle_status(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	int err;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = NVME_IO_MGMT_RECV_RUH_STATUS,
		.cdw11 = (data_len >> 2) - 1,
		.data_len = data_len,
		.out_data = &expected_data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_fdp_reclaim_unit_handle_status(test_link, TEST_NSID, &data, data_len, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_fdp_reclaim_unit_handle_update(void)
{
	__u16 pids;
	unsigned int npids = 1;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = NVME_IO_MGMT_SEND_RUH_UPDATE | ((npids - 1) << 16),
		.data_len = npids * sizeof(__u16),
		.in_data = &pids,
	};

	int err;

	arbitrary(&pids, sizeof(pids));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_fdp_reclaim_unit_handle_update(test_link, TEST_NSID, &pids,
						  npids, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_dim_send(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	__u32 result = 0;
	__u8 tas = 0xf;
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_discovery_info_mgmt,
		.cdw10 = tas,
		.data_len = data_len,
		.in_data = &expected_data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_dim_send(test_link, tas, &data, data_len, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_cdq(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8] = {};
	__u16 mos = 0x1;
	__u16 cdqid = 0x3;
	__u8 sel = NVME_LM_SEL_DELETE_CDQ;
	__u32 sz = 0x4;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ctrl_data_queue,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cdqid,
		.cdw12 = sz,
		.data_len = 0,
		.in_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_cdq(test_link, sel, mos, 0x2, sz, &data, &cdqid, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_track_send(void)
{
	__u8 sel = NVME_LM_SEL_DELETE_CDQ;
	__u16 cdqid = 0x3;
	__u32 result = 0;
	__u16 mos = 0x1;
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_track_send,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cdqid,
	};

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_track_send(test_link, sel, mos, cdqid, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_lm_migration_send(void)
{
	__u32 expected_data[8], data[8] = {};
	__u8 sel = NVME_LM_SEL_RESUME;
	__u64 offset = 0xffffffffff;
	__u32 numd = 8;
	__u16 cntlid = 0x2;
	__u32 result = 0;
	__u16 mos = 0x1;
	__u8 uidx = 0x4;
	__u8 stype = 0x1;
	__u8 csvi = 0x2;
	__u16 csuuidi = 0x13;
	bool dudmq = false;
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_migration_send,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cntlid,
		.cdw12 = (__u32)offset,
		.cdw13 = (__u32)(offset >> 32),
		.cdw14 = uidx,
		.cdw15 = numd,
		.data_len = numd << 2,
		.in_data = &data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_migration_send(test_link, sel, mos,
				     cntlid, stype, dudmq, csvi, csuuidi,
				     offset, uidx, &expected_data,
				     sizeof(expected_data), NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_migration_recv(void)
{
	__u8 sel = NVME_LM_SEL_GET_CONTROLLER_STATE;
	__u32 expected_data[8], data[8] = {};
	__u64 offset = 0xffffffffff;
	__u16 csuuidi = 0x3;
	__u32 numd = 8 - 1;
	__u16 cntlid = 0x2;
	__u8 csuidxp = 0x5;
	__u32 result = 0;
	__u16 mos = 0x1;
	__u8 uidx = 0x4;
	int err;

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_migration_receive,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cntlid | (csuuidi << 16) |
			 (csuidxp << 24),
		.cdw12 = (__u32)offset,
		.cdw13 = (__u32)(offset >> 32),
		.cdw14 = uidx,
		.cdw15 = numd,
		.data_len = (numd + 1) << 2,
		.out_data = &expected_data,
	};

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_migration_recv(test_link, offset, mos, cntlid, csuuidi, sel, uidx, csuidxp,
				     &data, sizeof(data), NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void run_test(const char *test_name, void (*test_fn)(void))
{
	printf("Running test %s...", test_name);
	fflush(stdout);
	test_fn();
	puts(" OK");
}

#define RUN_TEST(name) run_test(#name, test_##name)

int main(void)
{
	nvme_root_t r = nvme_create_root(stdout, DEFAULT_LOGLEVEL);

	set_mock_fd(TEST_FD);
	check(!nvme_open(r, "NVME_TEST_FD", &test_link), "opening test link failed");

	RUN_TEST(format_nvm);
	RUN_TEST(ns_mgmt);
	RUN_TEST(ns_mgmt_create);
	RUN_TEST(ns_mgmt_delete);
	RUN_TEST(get_property);
	RUN_TEST(set_property);
	RUN_TEST(ns_attach);
	RUN_TEST(ns_attach_ctrls);
	RUN_TEST(ns_detach_ctrls);
	RUN_TEST(fw_download);
	RUN_TEST(fw_commit);
	RUN_TEST(security_send);
	RUN_TEST(security_receive);
	RUN_TEST(get_lba_status);
	RUN_TEST(directive_send);
	RUN_TEST(directive_send_id_endir);
	RUN_TEST(directive_send_stream_release_identifier);
	RUN_TEST(directive_send_stream_release_resource);
	RUN_TEST(directive_recv);
	RUN_TEST(directive_recv_identify_parameters);
	RUN_TEST(directive_recv_stream_parameters);
	RUN_TEST(directive_recv_stream_status);
	RUN_TEST(directive_recv_stream_allocate);
	RUN_TEST(capacity_mgmt);
	RUN_TEST(lockdown);
	RUN_TEST(sanitize_nvm);
	RUN_TEST(dev_self_test);
	RUN_TEST(virtual_mgmt);
	RUN_TEST(flush);
	RUN_TEST(read);
	RUN_TEST(write);
	RUN_TEST(compare);
	RUN_TEST(write_zeros);
	RUN_TEST(write_uncorrectable);
	RUN_TEST(verify);
	RUN_TEST(dsm);
	RUN_TEST(copy);
	RUN_TEST(resv_acquire);
	RUN_TEST(resv_register);
	RUN_TEST(resv_release);
	RUN_TEST(resv_report);
	RUN_TEST(io_mgmt_recv);
	RUN_TEST(io_mgmt_send);
	RUN_TEST(fdp_reclaim_unit_handle_status);
	RUN_TEST(fdp_reclaim_unit_handle_update);
	RUN_TEST(dim_send);
	RUN_TEST(lm_cdq);
	RUN_TEST(lm_track_send);
	RUN_TEST(lm_migration_send);
	RUN_TEST(lm_migration_recv);

	nvme_free_root(r);
}
