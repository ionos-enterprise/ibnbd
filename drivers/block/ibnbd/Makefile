ibnbd-client-y := ibnbd-clt.o \
		  ibnbd-clt-sysfs.o

ibnbd-server-y := ibnbd-srv.o \
		  ibnbd-srv-dev.o \
		  ibnbd-srv-sysfs.o

ibnbd-core-y := ibnbd.o \
		ibnbd-proto.o

obj-$(CONFIG_BLK_DEV_IBNBD)        += ibnbd-core.o
obj-$(CONFIG_BLK_DEV_IBNBD_CLIENT) += ibnbd-client.o
obj-$(CONFIG_BLK_DEV_IBNBD_SERVER) += ibnbd-server.o
