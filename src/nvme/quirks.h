// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#ifndef QUIRKS_H_
#define QUIRKS_H_

#include <asm/types.h>

enum {
	NVME_QUIRKS_NS_ID_DESC_LIST = (1 << 0),
};

unsigned int nvme_quirks_get(__u16 vid, __u16 did);

#endif /* QUIRKS_H_ */
