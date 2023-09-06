// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <json.h>

#include "private.h"
#include "quirks.h"

static struct nvme_quirk *quirk_table;
static unsigned int quirk_table_length;

unsigned int nvme_quirks_get(__u16 vid, __u16 did)
{
	struct nvme_quirk *q;
	int i;

	if (!quirk_table)
		return 0;

	for (i = 0; i < quirk_table_length; i++) {
		q = &quirk_table[i];

		if (q->vid == vid && q->did == did)
			return q->flags;
	}

	return 0;
}

static void quirks_parse_entry(struct json_object *entry, __u16 *vid, __u16 *did,
			       unsigned int *flags)
{
	struct json_object *o, *q;
	unsigned int _flags;
	__u16 _vid, _did;
	const char *s;
	char *endptr;
	int i;

	o = json_object_object_get(entry, "vid");
	if (!o)
		return;
	s = json_object_get_string(o);
	if (!s)
		return;

	errno = 0;
	_vid = strtol(s, &endptr, 0);
	if (errno != 0 || endptr == s)
		return;

	o = json_object_object_get(entry, "did");
	if (!o)
		return;
	s = json_object_get_string(o);
	if (!s)
		return;

	errno = 0;
	_did = strtol(s, &endptr, 0);
	if (errno != 0 || endptr == s)
		return;

	o = json_object_object_get(entry, "quirks");
	if (!json_object_is_type(o, json_type_array))
		return;

	_flags = 0;
	for (i = 0; i < json_object_array_length(o); i++) {
		q = json_object_array_get_idx(o, i);
		if (!q)
			continue;

		s = json_object_get_string(q);
		if (!s)
			continue;

		if (!strcmp("NS_ID_DESC_LIST", s))
			_flags |= NVME_QUIRKS_NS_ID_DESC_LIST;
	}

	*vid = _vid;
	*did = _did;
	*flags = _flags;

	return;
}

static void quirks_parse(int fd)
{
	struct json_object *root, *o;
	struct nvme_quirk *q;
	int i;

	root = parse_json(NULL, fd);
	if (!root)
		return;

	if (!json_object_is_type(root, json_type_array)) {
		json_object_put(root);
		return;
	}

	quirk_table_length = json_object_array_length(root);
	quirk_table = calloc(quirk_table_length, sizeof(*q));
	if (!quirk_table)
		return;

	for (i = 0; i < json_object_array_length(root); i++) {
		o = json_object_array_get_idx(root, i);
		if (!o)
			continue;

		q = &quirk_table[i];
		quirks_parse_entry(o, &q->vid, &q->did, &q->flags);
	}

}

static void __attribute__ ((constructor (101))) load_quirk_table()
{
	char *path, *env;
	int fd, ret;

	env = getenv("NVME_CONFIG_QUIRKS");
	if (!env) {
		ret = asprintf(&path, "%s/nvme/quirks.json\n", SYSCONFDIR);
		if (ret < 0)
			return;
	} else
		path = env;

	fd = open(path, O_RDONLY);
	quirks_parse(fd);

	if (!env)
		free(path);
	close(fd);
}

static void __attribute__ ((destructor (101))) free_quirk_table()
{
	if (!quirk_table)
		return;

	free(quirk_table);
}
