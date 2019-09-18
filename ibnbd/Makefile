# SPDX-License-Identifier: GPL-2.0-or-later

ccflags-y := -Idrivers/infiniband/ulp/ibtrs

ibnbd-client-y := ibnbd-clt.o \
		  ibnbd-common.o \
		  ibnbd-clt-sysfs.o

ibnbd-server-y := ibnbd-srv.o \
		  ibnbd-common.o \
		  ibnbd-srv-dev.o \
		  ibnbd-srv-sysfs.o

obj-$(CONFIG_BLK_DEV_IBNBD_CLIENT) += ibnbd-client.o
obj-$(CONFIG_BLK_DEV_IBNBD_SERVER) += ibnbd-server.o

-include $(src)/compat/compat.mk
