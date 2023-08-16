// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023
 *
 * Authors: Vikash Kumar <vikash.k5@samsung.com>
 */
#ifndef _HANDLE_H
#define _HANDLE_H

#include <getopt.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include "mi.h"

struct nvme_dev {
        enum nvme_dev_type type;
        union {
                struct {
                        struct dev_handle hdl;
                        struct stat stat;
                } direct;
                struct {
                        nvme_root_t root;
                        nvme_mi_ep_t ep;
                        nvme_mi_ctrl_t ctrl;
                } mi;
        };

        const char *name;
};

#define dev_hdl(d) __dev_hdl(d, __func__, __LINE__)

static inline struct dev_handle* __dev_hdl(struct nvme_dev *dev, const char *func, int line)
{
        if (dev->type != NVME_DEV_DIRECT) {
                fprintf(stderr,
                        "warning: %s:%d not a direct transport!\n",
                        func, line);
                return NULL;
        }
        return &(dev->direct.hdl);
}

static inline nvme_mi_ep_t dev_mi_ep(struct nvme_dev *dev)
{
        if (dev->type != NVME_DEV_MI) {
                fprintf(stderr,
                        "warning: not a MI transport!\n");
                return NULL;
        }
        return dev->mi.ep;
}

int get_dev(struct nvme_dev **dev, int argc, char **argv, int flags);

void dev_close(struct nvme_dev *dev);

#endif /* _HANDLE_H */
