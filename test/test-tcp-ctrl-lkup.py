import json
import shutil
import ipaddress
import subprocess
from argparse import ArgumentParser

parser = ArgumentParser(
    description='Generate code used to test whether libnvme can match a candidate controller to an existing one.'
)
parser.add_argument(
    '--out',
    action='store',
    help='Output file (default: %(default)s)',
    default='test-tcp-ctrl-lkup.c',
    type=str,
    metavar='FILE',
)
ARGS = parser.parse_args()

# This script depends on package iproute2 being installed.
IP = shutil.which('ip')

LINE = r'''
	/*******************************************************************/'''

HEADER = r'''// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2023 Martin Belanger, Dell Technologies Inc.
 *
 * This file was auto-generated. Do not edit.
 *
 * This test is for tcp only. It is used to check whether libnvme
 * is able to match a candidate controller to an existing controller
 * when host_traddr and/or host_iface are used in the configuration.
 *
 * This test uses the actual interface map on the system to make
 * sure that the underlying libnvme code will be able retrieve the
 * "real" data from the system.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnvme.h>
#include <nvme/private.h>

#define DEFAULT_SUBSYSNAME "subsysname"
#define DEFAULT_SUBSYSNQN "subsysnqn"

static bool success = true;

struct ctrl_args {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;
	const char *address;
};

void set_args(struct ctrl_args *args,
	      const char *transport,
	      const char *traddr,
	      const char *trsvcid,
	      const char *host_traddr,
	      const char *host_iface,
	      const char *address)
{
	args->transport   = transport;
	args->traddr      = traddr;
	args->trsvcid     = trsvcid;
	args->host_traddr = host_traddr;
	args->host_iface  = host_iface;
	args->address     = address;
}

void test(int family,
	  int reference_id,
	  int candidate_id,
	  struct ctrl_args *reference,
	  struct ctrl_args *candidate,
	  bool should_match)
{
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t reference_ctrl; /* Existing controller (from sysfs) */
	nvme_ctrl_t candidate_ctrl;
	nvme_subsystem_t s;

	r = nvme_create_root(stdout, LOG_DEBUG);
	assert(r);

	h = nvme_default_host(r);
	assert(h);

	s = nvme_lookup_subsystem(h, DEFAULT_SUBSYSNAME, DEFAULT_SUBSYSNQN);
	assert(s);

	reference_ctrl = nvme_lookup_ctrl(s, reference->transport, reference->traddr,
					  reference->host_traddr, reference->host_iface,
					  reference->trsvcid, NULL);
	assert(reference_ctrl);
	reference_ctrl->name = "nvme1";  /* fake the device name */
	if (reference->address) {
		reference_ctrl->address = (char *)reference->address;
	}

	candidate_ctrl = nvme_lookup_ctrl(s, candidate->transport, candidate->traddr,
					  candidate->host_traddr, candidate->host_iface,
					  candidate->trsvcid, NULL);

	if (should_match) {
		if (candidate_ctrl != reference_ctrl) {
			printf("IPv%d-%d-%d: Candidate (%s, %s, %s, %s, %s) failed to match (%s, %s, %s, %s, %s, %s)\n",
			       family, reference_id, candidate_id,
			       candidate->transport, candidate->traddr, candidate->trsvcid,
			       candidate->host_traddr, candidate->host_iface,
			       reference->transport, reference->traddr, reference->trsvcid,
			       reference->host_traddr, reference->host_iface, reference->address);
			success = false;
		}
	} else {
		if (candidate_ctrl == reference_ctrl) {
			printf("IPv%d-%d-%d: Candidate (%s, %s, %s, %s, %s) should not match (%s, %s, %s, %s, %s, %s)\n",
			       family, reference_id, candidate_id,
			       candidate->transport, candidate->traddr, candidate->trsvcid,
			       candidate->host_traddr, candidate->host_iface,
			       reference->transport, reference->traddr, reference->trsvcid,
			       reference->host_traddr, reference->host_iface, reference->address);
			success = false;
		}
	}
}

int main(int argc, char *argv[])
{
	struct ctrl_args reference = {0};
	struct ctrl_args candidate = {0};'''


FOOTER = r'''
	fflush(stdout);

	exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}'''

STUB = '''#include <stdlib.h>
int main(int argc, char *argv[])
{
	exit(EXIT_SUCCESS);
}'''


def set_args(obj, traddr, host_traddr, host_iface, address=None):
    host_traddr = 'NULL' if host_traddr is None else f'"{host_traddr}"'
    host_iface = 'NULL' if host_iface is None else f'"{host_iface}"'
    address = 'NULL' if address is None else f'"{address}"'
    return rf'''	set_args(&{obj}, "tcp", "{traddr}", "8009", {host_traddr}, {host_iface}, {address});'''


def print_test_sequence(family, traddr, ifname, primary_addr, f):
    # make up an alternate address slightly different from the primary address
    alt_addr = (ipaddress.ip_address(primary_addr) + 1).compressed

    lo_addr = '127.0.0.1' if family == 4 else '::1'

    # This is the list of candidates we're trying to match
    candidates = {
        0: (None, None),  # (host-traddr, host-iface)
        1: (primary_addr, None),
        2: (None, ifname),
        3: (primary_addr, ifname),
        4: (alt_addr, None),
        5: (alt_addr, ifname),
        6: (None, 'lo'),
        7: (primary_addr, 'lo'),
        8: (alt_addr, 'lo'),
    }

    # This is a list of reference controllers (i.e. existing controllers)
    # that we're going to match each candidate against. We list the expected
    # result (True for "match", False for "no match") for each of the candidates
    # defined above. A "match" means that the reference controller can be
    # reused for the candidate configuration.
    tests = {
        1: {
            'reference': (None, None, None),  # (host-traddr, host-iface, address)
            'expected-result': {
                0: True,
                1: True,
                2: True,
                3: True,
                4: True,
                5: True,
                6: True,
                7: True,
                8: True,
            },
        },
        2: {
            'reference': (primary_addr, None, None),  # (host-traddr, host-iface, address)
            'expected-result': {
                0: True,
                1: True,
                2: True,
                3: True,
                4: False,
                5: False,
                6: False,
                7: False,
                8: False,
            },
        },
        3: {
            'reference': (None, ifname, None),  # (host-traddr, host-iface, address)
            'expected-result': {
                0: True,
                1: True,
                2: True,
                3: True,
                4: False,
                5: False,
                6: False,
                7: False,
                8: False,
            },
        },
        4: {
            'reference': (primary_addr, ifname, None),  # (host-traddr, host-iface, address)
            'expected-result': {
                0: True,
                1: True,
                2: True,
                3: True,
                4: False,
                5: False,
                6: False,
                7: False,
                8: False,
            },
        },
        5: {
            'reference': (alt_addr, None, None),  # (host-traddr, host-iface, address)
            'expected-result': {
                0: True,
                1: False,
                2: False,
                3: False,
                4: True,
                5: False,
                6: False,
                7: False,
                8: False,
            },
        },
        6: {
            'reference': (
                None,  # host-traddr
                None,  # host-iface
                f'traddr={traddr},trsvcid=8009,src_addr={primary_addr}',  # address
            ),
            'expected-result': {
                0: True,
                1: True,
                2: True,
                3: True,
                4: False,
                5: False,
                6: False,
                7: False,
                8: False,
            },
        },
        7: {
            'reference': (
                None,  # host-traddr
                None,  # host-iface
                f'traddr={traddr},trsvcid=8009,src_addr={lo_addr}',  # address
            ),
            'expected-result': {
                0: True,
                1: False,
                2: False,
                3: False,
                4: False,
                5: False,
                6: True,
                7: False,
                8: False,
            },
        },
    }

    for reference_id, test in tests.items():
        print(LINE, file=f)
        print(f'	/* IPv{family}: Reference ID {reference_id} */', file=f)
        reference_args = test['reference']
        print(set_args('reference', traddr, *reference_args), file=f)

        for candidate_id, expected_result in test['expected-result'].items():
            candidate_args = candidates[candidate_id]
            print(set_args('candidate', traddr, *candidate_args), file=f)
            print(
                rf'	test({family}, {reference_id}, {candidate_id}, &reference, &candidate, {"true" if expected_result else "false"});',
                file=f,
            )


def get_ifaces():
    '''Get the list of interfaces on the local system'''
    try:
        cmd = [IP, '-j', 'address', 'show']
        p = subprocess.run(cmd, stdout=subprocess.PIPE, check=True)
        json_ifaces = json.loads(p.stdout.decode().strip())
    except subprocess.CalledProcessError:
        json_ifaces = []

    ifaces = {}
    for iface in json_ifaces:
        addr_info = iface.get('addr_info')
        if addr_info:
            ifname = iface['ifname']
            if ifname != 'lo':
                ifaces[ifname] = {}
                for info in addr_info:
                    family = 4 if info['family'] == 'inet' else 6
                    ifaces[ifname].setdefault(family, []).append(info['local'])

    return ifaces


if __name__ == '__main__':
    with open(ARGS.out, mode='w') as f:
        if IP:
            print(HEADER, file=f)

            ifaces = get_ifaces()
            for ifname, addresses in ifaces.items():
                if 4 in addresses and 6 in addresses:
                    print_test_sequence(4, '123.123.123.123', ifname, addresses[4][0], f)

                    print_test_sequence(6, 'aaaa::bbbb', ifname, addresses[6][0], f)
                    break

            print(FOOTER, file=f, flush=True)
        else:
            print(STUB, file=f, flush=True)
