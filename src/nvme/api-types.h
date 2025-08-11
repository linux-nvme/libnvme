// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Types used as part of the libnvme/libnvme-mi API, rather than specified
 * by the NVM Express specification.
 *
 * These are shared across both libnvme and libnvme-mi interfaces.
 *
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */
#ifndef _LIBNVME_API_TYPES_H
#define _LIBNVME_API_TYPES_H

#include <stdio.h>
#include <stdbool.h>

#include <nvme/types.h>

struct nvme_root;
typedef struct nvme_root *nvme_root_t;
struct nvme_link;
typedef struct nvme_link *nvme_link_t;

/**
 * nvme_create_root() - Initialize root object
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use
 *
 * Return: Initialized &nvme_root_t object
 */
nvme_root_t nvme_create_root(FILE *fp, int log_level);

/**
 * nvme_free_root() - Free root object
 * @r:	&nvme_root_t object
 *
 * Free an &nvme_root_t object and all attached objects
 */
void nvme_free_root(nvme_root_t r);

#endif /* _LIBNVME_API_TYPES_H */
