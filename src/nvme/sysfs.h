/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 */

#ifndef _LIBNVME_SYSFS_H
#define _LIBNVME_SYSFS_H

/**
 * DOC: sysfs.h
 *
 * libnvme sysfs directory
 */

/**
 * nvme_ctrl_sysfs_dir() - Return for a NVMe controller sysfs directory
 *
 * Return: NVMe controller sysfs directory
 */
const char *nvme_ctrl_sysfs_dir(void);

#endif /* _LIBNVME_SYSFS_H */
