# SPDX-License-Identifier: GPL-2.0-or-later

# Called as kbuild
ifneq ($(KERNELRELEASE),)

ifdef PKG_VERSION
DEFINES += -D RNBD_VER_STRING=\"$(PKG_VERSION)\"
DEFINES += -D RTRS_VER_STRING=\"$(PKG_VERSION)\"
endif

# rnbd requires public header of rtrs API
KBUILD_CFLAGS += $(DEFINES) -I$(src)/rtrs

export CONFIG_BLK_DEV_RNBD        := y
export CONFIG_BLK_DEV_RNBD_CLIENT := m
export CONFIG_BLK_DEV_RNBD_SERVER := m

export CONFIG_INFINIBAND_RTRS        := m
export CONFIG_INFINIBAND_RTRS_CLIENT := m
export CONFIG_INFINIBAND_RTRS_SERVER := m

obj-m += rtrs/
obj-m += rnbd/

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
