# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2024 SUSE LLC.
#
# Authors: Daniel Wagner <dwagner@suse.de>


sysfs = executable(
    'test-sysfs',
    ['sysfs.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

test_cases = [
    'tw-carbon-6.8.0-rc1+',
    'empty',
]

setup = find_program('setup.sh')

foreach test_case : test_cases
    r = run_command(setup, files('data'/test_case + '.tar.xz'), meson.current_build_dir(), check: true)
    i = r.stdout().strip()
    env = environment()
    env.set('LIBNVME_SYSFS_PATH', i)
    env.set(
        'LIBNVME_HOSTNQN',
        'nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6',
    )
    env.set('LIBNVME_HOSTID', 'ce4fee3e-c02c-11ee-8442-830d068a36c6')
    test(
        'sysfs-' + test_case,
        sysfs,
        args : [ i, test_case + '.out', files('data'/test_case + '.out') ],
        env : env,
    )
endforeach
