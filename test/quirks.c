// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdio.h>

#include <libnvme.h>

static bool test_quirk(unsigned int vid, unsigned int did, unsigned int flags)
{
	bool pass = true;

	printf("%04x:%04x == %x ", vid, did, flags);
	if (nvme_quirks_get(0,0) != 0)
		pass &= false;

	printf("%s\n", pass ? "[PASS]" : "[FAILED]");

	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	printf("test quirk database loading/parsing\n");
	pass &= test_quirk(0, 0, 0x0);
	pass &= test_quirk(0x1234, 0x5678, 0x1);

	return pass? 0 : 1;
}
