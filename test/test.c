// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * Basic libnvme test: uses scan filters, single controllers, and many admin
 * command APIs for identifications, logs, and features. No verification for
 * specific values are performed: the test will only report which commands
 * executed were completed successfully or with an error. User inspection of
 * the output woould be required to know if everything is working when the
 * program exists successfully; an ungraceful exit means a bug exists
 * somewhere.
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <uuid.h>
#include <libnvme.h>

#include <ccan/endian/endian.h>

static bool nvme_match_subsysnqn_filter(nvme_subsystem_t s,
		nvme_ctrl_t c, nvme_ns_t ns, void *f_args)
{
	char *nqn_match = f_args;

	if (s)
		return strcmp(nvme_subsystem_get_nqn(s), nqn_match) == 0;
	return true;
}

static int test_ctrl(nvme_ctrl_t c)
{
	static __u8 buf[0x1000];

	enum nvme_get_features_sel sel = NVME_GET_FEATURES_SEL_CURRENT;
	int ret, temp, fd = nvme_ctrl_get_fd(c);
	struct nvme_error_log_page error[64]; 
	struct nvme_smart_log smart = { 0 };
	struct nvme_firmware_slot fw =  { 0 };
	struct nvme_ns_list ns_list = { 0 };
	struct nvme_cmd_effects_log cfx = { 0 };
	struct nvme_self_test_log st = { 0 };
	struct nvme_telemetry_log *telem = (void *)buf;
	struct nvme_endurance_group_log eglog = { 0 };
	struct nvme_ana_group_desc *analog = (void *)buf;
	struct nvme_resv_notification_log resvnotify = { 0 };
	struct nvme_sanitize_log_page sanlog = { 0 };
	struct nvme_id_uuid_list uuid = { 0 };
	struct nvme_id_ns_granularity_list gran = { 0 };
	struct nvme_secondary_ctrl_list sec = { 0 };
	struct nvme_primary_ctrl_cap prim = { 0 };
	struct nvme_ctrl_list ctrlist = { 0 };
	struct nvme_id_ctrl id = { 0 };

	__u32 result;

	ret = nvme_ctrl_identify(c, &id);
	if (ret) {
		printf("ERROR: no identify for:%s\n", nvme_ctrl_get_name(c));
		return ret;
	}
	else {
		printf("PASSED: Identify controller\n");
	}

	ret = nvme_get_log_smart(fd, NVME_NSID_ALL, true, &smart);
	if (ret) {
		printf("ERROR: no smart log for:%s %#x\n", nvme_ctrl_get_name(c), ret);
		return ret;
	}
	else {
		printf("PASSED: smart log\n");
	}

	temp = ((smart.temperature[1] << 8) | smart.temperature[0]) - 273;
	printf("Controller:%s\n", nvme_ctrl_get_name(c));
	printf("\nIdentify:\n");
	printf("  vid:%#04x\n", le16_to_cpu(id.vid));
	printf("  ssvid:%#04x\n", le16_to_cpu(id.ssvid));
	printf("  oacs:%#x\n", id.oacs);
	printf("  lpa:%#x\n", id.lpa);
	printf("  sn:%-.20s\n", id.sn);
	printf("  model:%-.40s\n", id.mn);

	ret = nvme_identify_allocated_ns_list(fd, 0, &ns_list);
	printf("%s: %x\n", ret ? "ERROR: Allocated NS List" : "PASSED: Allocated NS List", ret);
	ret = nvme_identify_active_ns_list(fd, 0, &ns_list);
	printf("%s: %x\n", ret ? "ERROR: Active NS List" : "PASSED: Active NS List", ret);
	ret = nvme_identify_ctrl_list(fd, 0, &ctrlist);
	printf("%s: %x\n", ret ? "ERROR: Ctrl List" : "PASSED: Ctrl List", ret);
	ret = nvme_identify_nsid_ctrl_list(fd, 1, 0, &ctrlist);
	printf("%s: %x\n", ret ? "ERROR: NSID Ctrl List" : "PASSED: NSID Ctrl List", ret);
	ret = nvme_identify_primary_ctrl(fd, 0, &prim);
	printf("%s: %x\n", ret ? "ERROR: Identify Primary" : "PASSED: Identify Primary", ret);
	ret = nvme_identify_secondary_ctrl_list(fd, 1, 0, &sec);
	printf("%s: %x\n", ret ? "ERROR: Identify Secondary" : "PASSED: Identify Secondary", ret);
	ret = nvme_identify_ns_granularity(fd, &gran);
	printf("%s: %x\n", ret ? "ERROR: Identify NS granularity" : "PASSED: Identify NS granularity", ret);
	ret = nvme_identify_uuid(fd, &uuid);
	printf("%s: %x\n", ret ? "ERROR: Identify UUID List" : "PASSED: Identify UUID List", ret);

	printf("\nLogs\n");
	printf("  SMART: Current temperature:%d percent used:%d%%\n", temp,
		smart.percent_used);
	ret = nvme_get_log_sanitize(fd, true, &sanlog);
	printf("%s: %x\n", ret ? "ERROR: Sanitize Log" : "PASSED: Sanitize Log", ret);
	ret = nvme_get_log_reservation(fd, true, &resvnotify);
	printf("%s: %x\n", ret ? "ERROR: Reservation Log" : "PASSED: Reservation Log", ret);
	ret = nvme_get_log_ana_groups(fd, true, sizeof(buf), analog);
	printf("%s: %x\n", ret ? "ERROR: ANA Groups" : "PASSED: ANA Groups", ret);
	ret = nvme_get_log_endurance_group(fd, 0, &eglog);
	printf("%s: %x\n", ret ? "ERROR: Endurance Group" : "PASSED: Endurance Group", ret);
	ret = nvme_get_log_telemetry_ctrl(fd, true, 0, sizeof(buf), telem);
	printf("%s: %x\n", ret ? "ERROR: Telemetry Controller" : "PASSED: Telemetry Controller", ret);
	ret = nvme_get_log_device_self_test(fd, &st);
	printf("%s: %x\n", ret ? "ERROR: Device Self Test" : "PASSED: Device Self Test", ret);
	ret = nvme_get_log_cmd_effects(fd, NVME_CSI_NVM, &cfx);
	printf("%s: %x\n", ret ? "ERROR: Command Effects" : "PASSED: Command Effects", ret);
	ret = nvme_get_log_changed_ns_list(fd, true, &ns_list);
	printf("%s: %x\n", ret ? "ERROR: Change NS List" : "PASSED: Change NS List", ret);
	ret = nvme_get_log_fw_slot(fd, true, &fw);
	printf("%s: %x\n", ret ? "ERROR: FW Slot" : "PASSED: FW Slot", ret);
	ret = nvme_get_log_error(fd, 64, true, error);
	printf("%s: %x\n", ret ? "ERROR: Error Log" : "PASSED: Error Log", ret);
	printf("\nFeatures\n");
	ret = nvme_get_features_arbitration(fd, sel, &result);
	if (!ret)
		printf("  Arbitration:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Arbitration:%x\n", ret);
	ret = nvme_get_features_power_mgmt(fd, sel, &result);
	if (!ret)
		printf("  Power Management:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Power Management:%x\n", ret);
	ret = nvme_get_features_temp_thresh(fd, sel, &result);
	if (!ret)
		printf("  Temperature Threshold:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Temperature Threshold:%x\n", ret);
	ret = nvme_get_features_err_recovery(fd, sel, &result);
	if (!ret)
		printf("  Error Recovery:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Error Recovery:%x\n", ret);
	ret = nvme_get_features_volatile_wc(fd, sel, &result);
	if (!ret)
		printf("  Volatile Write Cache:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Volatile Write Cache:%x\n", ret);
	ret = nvme_get_features_num_queues(fd, sel, &result);
	if (!ret)
		printf("  Number of Queues:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Number of Queues:%x\n", ret);
	ret = nvme_get_features_irq_coalesce(fd, sel, &result);
	if (!ret)
		printf("  IRQ Coalescing:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: IRQ Coalescing:%x\n", ret);
	ret = nvme_get_features_write_atomic(fd, sel, &result);
	if (!ret)
		printf("  Write Atomic:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Write Atomic:%x\n", ret);
	ret = nvme_get_features_async_event(fd, sel, &result);
	if (!ret)
		printf("  Asycn Event Config:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Asycn Event Config:%x\n", ret);
	ret = nvme_get_features_hctm(fd, sel, &result);
	if (!ret)
		printf("  HCTM:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: HCTM:%x\n", ret);
	ret = nvme_get_features_nopsc(fd, sel, &result);
	if (!ret)
		printf("  NOP Power State Config:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: NOP Power State Configrbitration:%x\n", ret);
	ret = nvme_get_features_rrl(fd, sel, &result);
	if (!ret)
		printf("  Read Recover Levels:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Read Recover Levels:%x\n", ret);
	ret = nvme_get_features_lba_sts_interval(fd, sel, &result);
	if (!ret)
		printf("  LBA Status Interval:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: LBA Status Interval:%x\n", ret);
	ret = nvme_get_features_sanitize(fd, sel, &result);
	if (!ret)
		printf("  Sanitize:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: SW Progress Marker:%x\n", ret);
	ret = nvme_get_features_sw_progress(fd, sel, &result);
	if (!ret)
		printf("  SW Progress Marker:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Sanitize:%x\n", ret);
	ret = nvme_get_features_resv_mask(fd, sel, &result);
	if (!ret)
		printf("  Reservation Mask:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Reservation Mask:%x\n", ret);
	ret = nvme_get_features_resv_persist(fd, sel, &result);
	if (!ret)
		printf("  Reservation Persistence:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Reservation Persistence:%x\n", ret);
	return 0;
}

static int test_namespace(nvme_ns_t n)
{
	int ret, nsid = nvme_ns_get_nsid(n), fd = nvme_ns_get_fd(n);
	struct nvme_id_ns ns = { 0 }, allocated = { 0 };
	struct nvme_ns_id_desc descs = { 0 };
	__u32 result = 0;
	__u8 flbas;

	ret = nvme_ns_identify(n, &ns);
	if (ret)
		return ret;

	nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &flbas);
	printf("%s: nsze:%" PRIu64 " lba size:%d\n",
		nvme_ns_get_name(n), le64_to_cpu(ns.nsze),
		1 << ns.lbaf[flbas].ds);

	ret = nvme_identify_allocated_ns(fd, nsid, &allocated);
	if (!ret)
		printf("  Identify allocated ns\n");
	else
		printf("  ERROR: Identify allocated ns:%x\n", ret);
	ret = nvme_identify_ns_descs(fd, nsid,  &descs);
	if (!ret)
		printf("  Identify NS Descriptors\n");
	else
		printf("  ERROR: Identify NS Descriptors:%x\n", ret);
	ret = nvme_get_features_write_protect(fd, nsid,
		NVME_GET_FEATURES_SEL_CURRENT, &result);
	if (!ret)
		printf("  Write Protect:%x\n", result);
	else if (ret > 0)
		printf("  ERROR: Write Protect:%x\n", ret);
	return 0;
}

static void print_hex(const uint8_t *x, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%02x", x[i]);
}

int main(int argc, char **argv)
{
	nvme_root_t r;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;
	const char *ctrl = "nvme4";
	const char *nqn_match = "testnqn";

	printf("Test filter for common loop back target\n");
	r = nvme_create_root(NULL, DEFAULT_LOGLEVEL);
	if (!r)
		return 1;
	nvme_scan_topology(r, nvme_match_subsysnqn_filter, (void *)nqn_match);
	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			printf("%s - NQN=%s\n", nvme_subsystem_get_name(s),
			       nvme_subsystem_get_nqn(s));
			nvme_subsystem_for_each_ctrl(s, c) {
				printf("  %s %s %s %s\n", nvme_ctrl_get_name(c),
				       nvme_ctrl_get_transport(c),
				       nvme_ctrl_get_address(c),
				       nvme_ctrl_get_state(c));
			}
		}
	}
	printf("\n");

	if (argc > 1)
		ctrl = argv[1];

	printf("Test scan specific controller\n");
	c = nvme_scan_ctrl(r, ctrl);
	if (c) {
		printf("%s %s %s %s\n", nvme_ctrl_get_name(c),
			nvme_ctrl_get_transport(c),
			nvme_ctrl_get_address(c),
			nvme_ctrl_get_state(c));
		nvme_free_ctrl(c);
	}
	printf("\n");
	nvme_free_tree(r);

	r = nvme_scan(NULL);
	if (!r)
		return -1;

	printf("Test walking the topology\n");
	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			printf("%s - NQN=%s\n", nvme_subsystem_get_name(s),
			       nvme_subsystem_get_nqn(s));
			nvme_subsystem_for_each_ctrl(s, c) {
				printf(" `- %s %s %s %s\n",
				       nvme_ctrl_get_name(c),
				       nvme_ctrl_get_transport(c),
				       nvme_ctrl_get_address(c),
				       nvme_ctrl_get_state(c));

				nvme_ctrl_for_each_ns(c, n) {
					char uuid_str[40];
					uuid_t uuid;
					printf("   `- %s lba size:%d lba max:%" PRIu64 "\n",
					       nvme_ns_get_name(n),
					       nvme_ns_get_lba_size(n),
					       nvme_ns_get_lba_count(n));
					printf("      eui:");
					print_hex(nvme_ns_get_eui64(n), 8);
					printf(" nguid:");
					print_hex(nvme_ns_get_nguid(n), 16);
					nvme_ns_get_uuid(n, uuid);
					uuid_unparse_lower(uuid, uuid_str);
					printf(" uuid:%s csi:%d\n", uuid_str,
					       nvme_ns_get_csi(n));
				}

				nvme_ctrl_for_each_path(c, p)
					printf("   `- %s %s\n",
					       nvme_path_get_name(p),
					       nvme_path_get_ana_state(p));
			}

			nvme_subsystem_for_each_ns(s, n) {
				printf(" `- %s lba size:%d lba max:%" PRIu64 "\n",
				       nvme_ns_get_name(n),
				       nvme_ns_get_lba_size(n),
				       nvme_ns_get_lba_count(n));
			}
		}
		printf("\n");
	}

	printf("Test identification, logs, and features\n");
	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				test_ctrl(c);
				printf("\n");
				nvme_ctrl_for_each_ns(c, n) {
					test_namespace(n);
					printf("\n");
				}
			}
			nvme_subsystem_for_each_ns(s, n) {
				test_namespace(n);
				printf("\n");
			}
		}
	}
	nvme_free_tree(r);

	return 0;
}
