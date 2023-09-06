// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include "quirks.h"

unsigned int nvme_quirks_get(__u16 vid, __u16 did)
{
	return 0;
}
