KDIR ?= $(srctree)
LIN_VER := $(shell V=linux/version.h; G=. ; \
        [ -f $(KDIR)/include/$${V} ] || G=generated/uapi ;\
        a=$$(grep LINUX_VERSION_CODE $(KDIR)/include/$${G}/linux/version.h | cut -f3 -d' '); \
	printf "%d.%d.%d" $$((a>>16)) $$(((a>>8) & 0xff)) $$((a & 0xff)))

dir := $(src)/compat

ifeq ($(LIN_VER),0.0.0)
$(error Failed to read linux/version.h and extract version)
endif

ifeq ($(LIN_VER), 4.4.73)
ccflags-y := -include $(dir)/compat-4.4.73.h -I$(dir)/include
obj-m += compat/4.4.73/
else ifeq ($(LIN_VER), 4.4.96)
ccflags-y := -include $(dir)/compat-4.4.96.h -I$(dir)/include
endif
