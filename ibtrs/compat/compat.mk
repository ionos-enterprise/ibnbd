KDIR ?= $(srctree)
LIN_VER := $(shell V=linux/version.h; G=. ; \
        [ -f $(KDIR)/include/$${V} ] || G=generated/uapi ;\
        a=$$(grep LINUX_VERSION_CODE $(KDIR)/include/$${G}/linux/version.h | cut -f3 -d' '); \
	printf "%d.%d.%d" $$((a>>16)) $$(((a>>8) & 0xff)) $$((a & 0xff)))

dir := $(src)/compat

ifeq ($(LIN_VER),0.0.0)
    $(error Failed to read linux/version.h and extract version)
else ifeq ($(LIN_VER), 4.4.112)
    do_compat := 1
else ifeq ($(LIN_VER), 4.14.93)
    do_compat := 1
else ifeq ($(LIN_VER), 4.14.86)
    do_compat := 1
else ifeq ($(LIN_VER), 4.14.110)
    do_compat := 1
else ifeq ($(LIN_VER), 4.14.120)
    do_compat := 1
else ifeq ($(LIN_VER), 4.19.46)
    do_compat := 1
endif

ifdef do_compat
    $(info - IBTRS with compat support for $(LIN_VER) kernel)
    ccflags-y := -include $(dir)/compat.h -I$(dir)/include

    ifdef IBTRS_USE_FMR
        $(info - IBTRS using FMR memory registration)
        ccflags-y += -DIBTRS_USE_FMR
    else
        $(info - IBTRS using default memory registration)
    endif

endif
