# SPDX-License-Identifier: GPL-2.0-or-later

# Called as kbuild
ifneq ($(KERNELRELEASE),)

ifdef PKG_VERSION
DEFINES += -D IBNBD_VER_STRING=\"$(PKG_VERSION)\"
DEFINES += -D IBTRS_VER_STRING=\"$(PKG_VERSION)\"
endif

# ibnbd requires public header of ibtrs API
KBUILD_CFLAGS += $(DEFINES) -I$(src)/ibtrs

export CONFIG_BLK_DEV_IBNBD        := y
export CONFIG_BLK_DEV_IBNBD_CLIENT := m
export CONFIG_BLK_DEV_IBNBD_SERVER := m

export CONFIG_INFINIBAND_IBTRS        := m
export CONFIG_INFINIBAND_IBTRS_CLIENT := m
export CONFIG_INFINIBAND_IBTRS_SERVER := m

obj-m += ibtrs/
obj-m += ibnbd/

# Normal Makefile, redirect to kbuild
else

KDIR ?= /lib/modules/`uname -r`/build

#
# ¯\(°_o)/¯ I dunno how to unite these two in one line
#

%:
	@$(MAKE) -C $(KDIR) M=$(PWD) $(MAKECMDGOALS)

all:
	@$(MAKE) -C $(KDIR) M=$(PWD) $(MAKECMDGOALS)

.PHONY: all

endif
