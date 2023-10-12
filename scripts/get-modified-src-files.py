#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2023 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>

"""List source files in current git repo that have been modified or are new (untracked)"""

import shutil
import subprocess

GIT = shutil.which("git")
SRC_FILES = (".c", ".h", ".cpp", ".cc")

cmd = f"{GIT} ls-files --modified --others --exclude-standard"
p = subprocess.run(
    cmd, stdout=subprocess.PIPE, check=True, universal_newlines=True, shell=True
)

modified_files = p.stdout.splitlines()
modified_src_files = [fname for fname in modified_files if fname.endswith(SRC_FILES)]

print(" ".join(modified_src_files))
