ibtrs-client-y := ibtrs-clt.o \
		  ibtrs-clt-sysfs.o

ibtrs-server-y := ibtrs-srv.o \
		  ibtrs-srv-sysfs.o

ibtrs-core-y := ibtrs.o \
		ibtrs-iu.o

obj-$(CONFIG_INFINIBAND_IBTRS)        += ibtrs-core.o
obj-$(CONFIG_INFINIBAND_IBTRS_CLIENT) += ibtrs-client.o
obj-$(CONFIG_INFINIBAND_IBTRS_SERVER) += ibtrs-server.o
