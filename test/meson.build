# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>

# These tests all require interaction with a real NVMe device, so we don't
# define as meson unit-tests, and therefore get run as part of the 'test'
# target. However, they're available for developer use, when hardware is
# available.

main = executable(
    'main-test',
    ['test.c'],
    dependencies: [libnvme_dep],
    include_directories: [incdir, internal_incdir]
)

if cxx_available
    cpp = executable(
        'test-cpp',
        ['cpp.cc'],
        dependencies: libnvme_dep,
        include_directories: [incdir, internal_incdir]
    )
endif

register = executable(
    'test-register',
    ['register.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

zns = executable(
    'test-zns',
    ['zns.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

mi = executable(
    'test-mi',
    ['mi.c', 'utils.c'],
    dependencies: libnvme_mi_test_dep,
    include_directories: [incdir, internal_incdir]
)

test('mi', mi)

mi_mctp = executable(
    'test-mi-mctp',
    ['mi-mctp.c', 'utils.c'],
    dependencies: libnvme_mi_test_dep,
    include_directories: [incdir, internal_incdir],
)

test('mi-mctp', mi_mctp)

uuid = executable(
    'test-uuid',
    ['uuid.c'],
    dependencies: libnvme_dep,
    include_directories: [incdir, internal_incdir]
)

test('uuid', uuid)

if conf.get('HAVE_NETDB')
    # make sure python is available (not available with muon)
    if find_program('python3').found()
        python3 = import('python').find_installation('python3', required: false)
        if python3.found()
            test_tcp_ctrl_lkup_c = custom_target(
                'test-tcp-ctrl-lkup.c',
                input : 'test-tcp-ctrl-lkup.py',
                output : 'test-tcp-ctrl-lkup.c',
                command : [python3, '@INPUT@', '--out', '@OUTPUT0@']
            )
            test_tcp_ctrl_lkup = executable(
                'test-tcp-ctrl-lkup',
                [test_tcp_ctrl_lkup_c],
                dependencies: libnvme_dep,
                include_directories: [incdir, internal_incdir]
            )
            test('Test TCP controller lookup', test_tcp_ctrl_lkup)
        endif
    endif

    tree = executable(
        'tree',
        ['tree.c'],
        dependencies: libnvme_dep,
        include_directories: [incdir, internal_incdir]
    )

    test('tree', tree)

    test_util = executable(
        'test-util',
        ['test-util.c'],
        include_directories: [incdir, internal_incdir]
    )
    test('Test util.c', test_util)
endif

subdir('nbft')
