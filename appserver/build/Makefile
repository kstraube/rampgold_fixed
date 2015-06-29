alll: all

include Makelocal

BUILD_DIR := $(shell pwd)
RAMP_LIB_DIR := $(BUILD_DIR)/ramplib
RAMP_BIN_DIR := $(BUILD_DIR)/rampbin
RAMP_INCLUDE_DIR := $(BUILD_DIR)/rampinclude
LIB_DIR := $(BUILD_DIR)/lib
BIN_DIR := $(BUILD_DIR)/bin
INCLUDE_DIR := $(BUILD_DIR)/include

CXX           := g++
CC            := gcc
LD            := ld
CFLAGS        := -fPIC -O3 -I.. -I$(INCLUDE_DIR) --param max-inline-insns-single=10000
CXXFLAGS      := $(CFLAGS) -Wno-pmf-conversions $(LOCAL_CXXFLAGS)
LDFLAGS       := -L$(LIB_DIR)
SPARC_APP_SETUID ?=
SPARC_APP_DEBUG_SETUID ?=

RAMP_TOOLCHAIN_PREFIX := sparc-ros-
RAMP_CXX      := $(RAMP_TOOLCHAIN_PREFIX)g++
RAMP_CC       := $(RAMP_TOOLCHAIN_PREFIX)gcc
RAMP_LD       := $(RAMP_TOOLCHAIN_PREFIX)ld
RAMP_CFLAGS   := -Os -I.. -I$(RAMP_INCLUDE_DIR) -std=gnu99
RAMP_CXXFLAGS := $(RAMP_CFLAGS)
RAMP_LDFLAGS  := -L$(RAMP_LIB_DIR) -L$(dir $(shell $(RAMP_CC) --print-libgcc-file-name))

all: functional functional-example \
     testappserver proxykernel-host $(LOCAL_TARGETS) 
	$(SPARC_APP_SETUID)
	$(SPARC_APP_DEBUG_SETUID)

include ../Common/Makefrag
include ../Functional/Makefrag
include ../TestAppServer/Makefrag
include ../ProxyKernel/Makefrag

ifeq ($(SETUID),TRUE)
SETUID_SUDO := sudo
endif
install: all uninstall
	$(SETUID_SUDO) mkdir -p $(INSTDIR)
	$(SETUID_SUDO) cp -R --preserve=all bin $(INSTDIR)/
	$(SETUID_SUDO) cp -R --preserve=all include $(INSTDIR)/
	$(SETUID_SUDO) cp -R --preserve=all lib $(INSTDIR)/
	$(SETUID_SUDO) cp -R --preserve=all rampbin $(INSTDIR)/
	$(SETUID_SUDO) cp -R --preserve=all rampinclude $(INSTDIR)/
	$(SETUID_SUDO) cp -R --preserve=all ramplib $(INSTDIR)/
	find $(INSTDIR) -name .svn* | $(SETUID_SUDO) xargs rm -rf 

uninstall:
	$(SETUID_SUDO) rm -rf $(INSTDIR)

clean: functional-clean common-clean testappserver-clean proxykernel-clean
	rm -rf $(BUILD_DIR)/obj
