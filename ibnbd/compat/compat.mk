LIN_VER := $(shell V=linux/version.h; G=. ; \
        [ -f $(srctree)/include/$${V} ] || G=generated/uapi ;\
        grep LINUX_VERSION_CODE $(srctree)/include/$${G}/linux/version.h | \
	awk '{printf "%d.%d.%d", and(rshift($$3,16),0xff), and(rshift($$3,8),0xff), and($$3, 0xff)}')

dir := $(srctree)/$(src)/compat

ifeq ($(LIN_VER), 4.4.73)
ccflags-y := -include $(dir)/compat-4.4.h
else ifeq ($(LIN_VER), 4.4.96)
ccflags-y := -include $(dir)/compat-4.4.h
endif
