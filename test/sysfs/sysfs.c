// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnvme.h>

static bool test_sysfs(const char *path, const char *filename)
{
	FILE *f;
	nvme_root_t r;
	int err;

	f = fopen(filename, "w");
	if (!f)
		return false;

	r = nvme_create_root(f, LOG_ERR);
	assert(r);

	err = nvme_scan_topology(r, NULL, NULL);
	if (!err)
		nvme_dump_tree(r);
	fprintf(f, "\n");

	nvme_free_tree(r);
	fclose(f);

	return err == 0;
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		fprintf(stderr, "usage: test-sysfs SYSFS_DIR OUTPUT_FILE COMPARE_FILE\n");
		return EXIT_FAILURE;
	}

	if (!test_sysfs(argv[1], argv[2]))
		return EXIT_FAILURE;

	if (execlp("diff", "diff", "-u", argv[3], argv[2], NULL))
		return EXIT_FAILURE;
}
