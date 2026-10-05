// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 * Check which DH-HMAC-CHAP host key a connect request carries, given the
 * keys of the configuration, a key set with nvme_host_set_dhchap_key()
 * and the secrets of the live controllers found by a topology scan, and
 * which host keys nvme_update_config() writes then.
 * The sysfs tree is created in a temporary directory, used via
 * LIBNVME_SYSFS_PATH. open() below fakes /dev/nvme-fabrics with one end
 * of a socket pair, the request is read from the other end.
 */

/* open() and its variants are defined below, without any redirection */
#undef _FILE_OFFSET_BITS
#undef _TIME_BITS
#undef _FORTIFY_SOURCE

#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <libnvme.h>

#define HOSTNQN		"nqn.2014-08.org.nvmexpress:uuid:3b3d1a3e-6f0e-4f3b-9d8a-0b5c1d2e3f40"
#define HOSTID		"3b3d1a3e-6f0e-4f3b-9d8a-0b5c1d2e3f40"
#define HOSTNQN2	"nqn.2014-08.org.nvmexpress:uuid:3b3d1a3e-6f0e-4f3b-9d8a-0b5c1d2e3f41"
#define HOSTID2		"3b3d1a3e-6f0e-4f3b-9d8a-0b5c1d2e3f41"
#define NQN(x)		"nqn.2014-08.org.nvmexpress:test-" x

/*
 * Placeholders, nothing but this test reads them. All but KEY_X have the
 * prefix of a secret, which libnvme does not require of a configured key.
 */
#define KEY_A	"DHHC-1:00:test-key-port-a"	/* port of subsystem A */
#define KEY_B	"DHHC-1:00:test-key-live-b"	/* live controller of subsystem B */
#define KEY_D	"DHHC-1:00:test-key-live-dd"	/* live controller of subsystem D */
#define KEY_H	"DHHC-1:00:test-key-host"	/* host key of the configuration */
#define KEY_M	"DHHC-1:00:test-key-live-mmm"	/* live controller of subsystem M */
#define KEY_S	"DHHC-1:00:test-key-set"	/* set with nvme_host_set_dhchap_key() */
#define KEY_X	"test-key-port-x"		/* port of subsystem A */
#define KEY_Y	"DHHC-1:00:test-key-live-yd"	/* live controller of subsystem Y */
#define KEY_Z	"DHHC-1:00:test-key-ctrl-z"	/* controller of subsystem Z */

/*
 * nvme1 to nvme8, scanned in this order: host NQN, host ID, subsystem NQN,
 * dhchap_secret. Of the secrets of B, M, Y and D, the last one, that of D,
 * is neither the first, the least, the greatest nor the longest, and has
 * the length and the last byte of the one scanned before it. The second
 * host has no live controller with a secret.
 */
static const char *live[][4] = {
	{ HOSTNQN, HOSTID, NQN("b"), KEY_B },
	{ HOSTNQN, HOSTID, NQN("m"), KEY_M },
	{ HOSTNQN, HOSTID, NQN("y"), KEY_Y },
	{ HOSTNQN, HOSTID, NQN("d"), KEY_D },	/* the last secret scanned */
	{ HOSTNQN, HOSTID, NQN("c"), "none" },	/* connected without a secret */
	{ HOSTNQN, HOSTID, NQN("e"), NULL },	/* no dhchap_secret attribute */
	{ HOSTNQN2, HOSTID2, NQN("f"), "none" },
	{ HOSTNQN2, HOSTID2, NQN("g"), NULL },
};

enum {
	SCAN = 1, SET_BEFORE = 2, SET_AFTER = 4, DUP = 8, LIVE_B = 16,
	HOST2 = 32, ADD = 64, DUMP = 128,
};

/*
 * The configuration has subsystem A with one port, A is not connected.
 * With SET_BEFORE or SET_AFTER, host_key is not configured, but set before
 * or after the scan. DUP sets duplicate_connect for that port, which must
 * not change the key; with LIVE_B, the request is for the live controller
 * of B instead of A. With ADD, it is for a new controller of subsystem Z
 * with the host key KEY_Z, created with nvme_create_ctrl() and connected
 * with nvmf_add_ctrl(), as 'nvme connect' and the Python bindings do. With
 * HOST2, the expected key is the host key of the second host instead. With
 * DUMP, it is the host key written, or with LIVE_B the key written for the
 * port of B.
 */
static const struct test {
	const char *name, *host_key, *port_key; /* keys of the configuration */
	int steps;
	const char *expect; /* sent, or with DUMP written; NULL: none */
} tests[] = {
	{ "host key", KEY_H, KEY_A, SCAN, KEY_H },
	{ "host key equal to the secret of B", KEY_B, KEY_A, SCAN, KEY_B },
	{ "host key 'none'", "none", KEY_A, SCAN, NULL },
	{ "empty host key", "", KEY_A, SCAN, NULL },
	{ "host key set before the scan", KEY_S, KEY_A, SET_BEFORE | SCAN, KEY_S },
	{ "host key set after the scan", KEY_S, KEY_A, SCAN | SET_AFTER, KEY_S },
	{ "last scanned secret set after the scan", KEY_D, KEY_A, SCAN | SET_AFTER, KEY_D },
	{ "host key 'none' set after the scan", "none", KEY_A, SCAN | SET_AFTER, NULL },
	{ "empty host key set after the scan", "", KEY_A, SCAN | SET_AFTER, NULL },
	{ "port key", NULL, KEY_A, SCAN, KEY_A },
	{ "port key 'none'", NULL, "none", SCAN, KEY_D },
	{ "empty port key", NULL, "", SCAN, KEY_D },
	{ "port key not in the form of a secret", NULL, KEY_X, SCAN, KEY_X },
	{ "no key", NULL, NULL, SCAN, KEY_D },
	{ "port key, nothing scanned", NULL, KEY_A, 0, KEY_A },
	{ "port key, duplicate_connect", NULL, KEY_A, SCAN | DUP, KEY_A },
	{ "host key, duplicate_connect", KEY_H, KEY_A, SCAN | DUP, KEY_H },
	{ "live controller of B", NULL, NULL, SCAN | LIVE_B, KEY_B },
	{ "host key, live controller of B", KEY_H, NULL, SCAN | LIVE_B, KEY_H },
	{ "controller added with nvmf_add_ctrl()", NULL, NULL, SCAN | ADD, KEY_Z },
	{ "second host, no secret scanned", NULL, NULL, SCAN | HOST2, NULL },
	{ "dump, no host key", NULL, KEY_A, SCAN | DUMP, NULL },
	{ "dump, host key", KEY_H, KEY_A, SCAN | DUMP, KEY_H },
	{ "dump, host key 'none'", "none", KEY_A, SCAN | DUMP, "none" },
	{ "dump, empty host key", "", KEY_A, SCAN | DUMP, "" },
	{ "dump, no host key, nothing scanned", NULL, KEY_A, DUMP, NULL },
	{ "dump, live controller of B", NULL, NULL, SCAN | DUMP | LIVE_B, KEY_B },
	{ NULL }
};

#define CONFIG	"config.json"
#define CTRL_DIR	"sys/class/nvme/"
#define SUBSYS_DIR	"sys/class/nvme-subsystem/"

static char dir[PATH_MAX];
static int peer = -1;

static int fake_open(const char *path, int flags, va_list ap)
{
	static const char reply[] = "instance=1,dhchap_secret\n";
	mode_t mode = flags & O_CREAT ? va_arg(ap, mode_t) : 0;
	int sv[2];

	if (strcmp(path, "/dev/nvme-fabrics"))
		return syscall(SYS_openat, AT_FDCWD, path, flags, mode);

	/* the reply serves as list of options and as answer to a connect */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv))
		return -1;
	if (write(sv[1], reply, strlen(reply)) < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	if (peer >= 0)
		close(peer);
	peer = sv[1];
	return sv[0];
}

int open(const char *path, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = fake_open(path, flags, ap);
	va_end(ap);
	return fd;
}

/* musl before 1.2.4 defines open64 as open with _GNU_SOURCE */
#undef open64
int open64(const char *path, int flags, ...) __attribute__((alias("open")));

/* With _FORTIFY_SOURCE, glibc's open() may call these, e.g. with clang */
int __open_2(const char *path, int flags)
{
	return open(path, flags);
}

int __open64_2(const char *path, int flags) __attribute__((alias("__open_2")));

/* Create the file @fmt with @value, or the directory @fmt if it is NULL */
__attribute__((format(printf, 2, 3)))
static bool put(const char *value, const char *fmt, ...)
{
	char path[128];
	va_list ap;
	FILE *f;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);
	if (len < 0 || len >= sizeof(path))
		return false;
	if (!value)
		return !mkdir(path, 0700);
	f = fopen(path, "w");
	if (!f)
		return false;
	fprintf(f, "%s\n", value);
	return !fclose(f);
}

/* The temporary directory becomes the working directory, @dir its path */
static bool setup_sysfs(void)
{
	const char *tmp = getenv("TMPDIR");
	int i;

	if (snprintf(dir, sizeof(dir), "%s/libnvme-dhchap-key-XXXXXX",
		     tmp ? tmp : "/tmp") >= sizeof(dir) || !mkdtemp(dir)) {
		dir[0] = '\0';
		return false;
	}
	if (chdir(dir))
		return false;
	/* relative if TMPDIR is, which neither libnvme nor nftw() can use now */
	if (!getcwd(dir, sizeof(dir))) {
		dir[0] = '\0';
		return false;
	}
	if (setenv("LIBNVME_SYSFS_PATH", dir, 1) ||
	    !put(NULL, "sys") || !put(NULL, "sys/class") ||
	    !put(NULL, CTRL_DIR) || !put(NULL, SUBSYS_DIR))
		return false;

	for (i = 1; i <= 8; i++) {
		const char *hostnqn = live[i - 1][0], *hostid = live[i - 1][1];
		const char *nqn = live[i - 1][2], *secret = live[i - 1][3];

		if (!put(NULL, SUBSYS_DIR "nvme-subsys%d", i) ||
		    !put(NULL, SUBSYS_DIR "nvme-subsys%d/nvme%d", i, i) ||
		    !put(nqn, SUBSYS_DIR "nvme-subsys%d/subsysnqn", i) ||
		    !put(NULL, CTRL_DIR "nvme%d", i) ||
		    !put(nqn, CTRL_DIR "nvme%d/subsysnqn", i) ||
		    !put("tcp", CTRL_DIR "nvme%d/transport", i) ||
		    !put("traddr=127.0.0.1,trsvcid=4420", CTRL_DIR "nvme%d/address", i) ||
		    !put(hostnqn, CTRL_DIR "nvme%d/hostnqn", i) ||
		    !put(hostid, CTRL_DIR "nvme%d/hostid", i) ||
		    (secret && !put(secret, CTRL_DIR "nvme%d/dhchap_secret", i)))
			return false;
	}
	return true;
}

static bool write_config(const struct test *t)
{
	FILE *f = fopen(CONFIG, "w");

	if (!f)
		return false;
	fprintf(f, "[{\"hostnqn\":\"%s\",\"hostid\":\"%s\",", HOSTNQN, HOSTID);
	if (t->host_key && !(t->steps & (SET_BEFORE | SET_AFTER)))
		fprintf(f, "\"dhchap_key\":\"%s\",", t->host_key);
	fprintf(f, "\"subsystems\":[{\"nqn\":\"%s\",\"ports\":[{", NQN("a"));
	if (t->port_key)
		fprintf(f, "\"dhchap_key\":\"%s\",", t->port_key);
	if (t->steps & DUP)
		fprintf(f, "\"duplicate_connect\":true,");
	fprintf(f, "\"transport\":\"tcp\",\"traddr\":\"127.0.0.2\",\"trsvcid\":\"4420\"");
	fprintf(f, "}]}]}]\n");
	return !fclose(f);
}

/* The dhchap_secret of the connect request, NULL if it has none */
static const char *sent_key(char *buf, size_t size)
{
	ssize_t len = peer < 0 ? -1 : recv(peer, buf, size - 1, MSG_DONTWAIT);
	char *p;

	if (len <= 0)
		return "(no request)";
	buf[len] = '\0';
	p = strstr(buf, ",dhchap_secret=");
	if (!p)
		return NULL;
	p += strlen(",dhchap_secret=");
	p[strcspn(p, ",\n")] = '\0';
	return p;
}

/* NULL is shown as (none), the empty string as "" */
static const char *show(const char *key)
{
	return !key ? "(none)" : key[0] ? key : "\"\"";
}

static bool run(const struct test *t)
{
	const char *key = "(no tree)";
	char buf[4096];
	struct nvme_fabrics_config cfg;
	nvme_root_t r, d = NULL;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	bool pass;

	if (peer >= 0)
		close(peer);
	peer = -1;

	r = nvme_create_root(stderr, LOG_ERR);
	if (r && write_config(t) && !nvme_read_config(r, CONFIG)) {
		h = nvme_lookup_host(r, HOSTNQN, HOSTID);
		if (t->steps & SET_BEFORE)
			nvme_host_set_dhchap_key(h, t->host_key);
		if (t->steps & SCAN)
			nvme_scan_topology(r, NULL, NULL);
		if (t->steps & SET_AFTER)
			nvme_host_set_dhchap_key(h, t->host_key);
		if (t->steps & HOST2) {
			h = nvme_lookup_host(r, HOSTNQN2, HOSTID2);
			key = nvme_first_subsystem(h) ?
			      nvme_host_get_dhchap_key(h) : "(not scanned)";
		} else if (t->steps & ADD) {
			c = nvme_create_ctrl(r, NQN("z"), "tcp", "127.0.0.3",
					     NULL, NULL, "4420");
			if (c) {
				nvme_ctrl_set_dhchap_host_key(c, KEY_Z);
				nvmf_default_config(&cfg);
				/* added to the tree if it succeeds */
				if (nvmf_add_ctrl(h, c, &cfg))
					nvme_free_ctrl(c);
				key = sent_key(buf, sizeof(buf));
			}
		} else if (t->steps & DUMP) {
			d = nvme_create_root(stderr, LOG_ERR);
			key = "(no dump)";
			unlink(CONFIG);
			if (d && !nvme_update_config(r) && !access(CONFIG, F_OK) &&
			    !nvme_read_config(d, CONFIG)) {
				h = nvme_lookup_host(d, HOSTNQN, HOSTID);
				key = nvme_host_get_dhchap_key(h);
				if (t->steps & LIVE_B) {
					s = nvme_lookup_subsystem(h, NULL, NQN("b"));
					c = nvme_subsystem_first_ctrl(s);
					key = c ? nvme_ctrl_get_dhchap_host_key(c) :
					      "(no port)";
				}
			}
		} else {
			s = nvme_lookup_subsystem(h, NULL, t->steps & LIVE_B ?
						  NQN("b") : NQN("a"));
			nvmf_connect_ctrl(nvme_subsystem_first_ctrl(s));
			key = sent_key(buf, sizeof(buf));
		}
	}

	pass = key && t->expect ? !strcmp(key, t->expect) : key == t->expect;
	printf("%s: %s, expected %s: %s\n", t->name, show(key),
	       show(t->expect), pass ? "PASS" : "FAIL");
	nvme_free_tree(d);
	nvme_free_tree(r);
	return pass;
}

static int rm(const char *path, const struct stat *st, int flag,
	      struct FTW *ftw)
{
	return remove(path);
}

int main(void)
{
	const struct test *t;
	bool pass = setup_sysfs();

	if (!pass)
		perror("fake sysfs tree");
	else
		for (t = tests; t->name; t++)
			pass = run(t) && pass;
	if (dir[0])
		nftw(dir, rm, 8, FTW_DEPTH | FTW_PHYS);
	return pass ? 0 : 1;
}
