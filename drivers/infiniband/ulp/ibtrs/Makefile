ibtrs-client-y := ibtrs-clt.o \
		  ibtrs-clt-stats.o \
		  ibtrs-clt-sysfs.o

ibtrs-server-y := ibtrs-srv.o \
		  ibtrs-srv-stats.o \
		  ibtrs-srv-sysfs.o

ibtrs-core-y := ibtrs.o

obj-$(CONFIG_INFINIBAND_IBTRS)        += ibtrs-core.o
obj-$(CONFIG_INFINIBAND_IBTRS_CLIENT) += ibtrs-client.o
obj-$(CONFIG_INFINIBAND_IBTRS_SERVER) += ibtrs-server.o

-include $(src)/compat/compat.mk
