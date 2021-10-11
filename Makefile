# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
.DEFAULT_GOAL := libnvme
BUILD-DIR     := .build

${BUILD-DIR}:
	./configure
	@echo "Configuration located in: $@"
	@echo "-------------------------------------------------------"

.PHONY: libnvme
libnvme: ${BUILD-DIR}
	ninja -C ${BUILD-DIR}

.PHONY: install test
install test: ${BUILD-DIR}
	cd ${BUILD-DIR} && meson $@

.PHONY: clean
clean:
ifneq ("$(wildcard ${BUILD-DIR})","")
	ninja -C ${BUILD-DIR} -t $@
endif

.PHONY: purge
purge:
ifneq ("$(wildcard ${BUILD-DIR})","")
	rm -rf ${BUILD-DIR}
endif

