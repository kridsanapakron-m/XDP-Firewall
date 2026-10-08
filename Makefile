ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
ARCH_INCLUDE := aarch64-linux-gnu
else
ARCH_INCLUDE := x86_64-linux-gnu
endif

CLANG ?= clang
CC ?= cc
CFLAGS_BPF := -O2 -g -target bpf -I/usr/include/$(ARCH_INCLUDE)
CFLAGS_CTL := -O2 -Wall -I/usr/include/$(ARCH_INCLUDE)
LDLIBS_CTL := -lbpf

BPF_OBJECTS := xdp_lb.o xdp_lb_deencap.o
CTL_BINARY := xdp_lb_ctl
CONF_BINARY := xdp_lb_conf

all: $(BPF_OBJECTS) $(CTL_BINARY) $(CONF_BINARY)

xdp_lb.o: xdp_lb.c xdp_lb_common.h
	$(CLANG) $(CFLAGS_BPF) -c xdp_lb.c -o $@

xdp_lb_deencap.o: xdp_lb_deencap.c
	$(CLANG) $(CFLAGS_BPF) -c xdp_lb_deencap.c -o $@

$(CTL_BINARY): xdp_lb_ctl.c xdp_lb_common.h
	$(CC) $(CFLAGS_CTL) xdp_lb_ctl.c -o $@ $(LDLIBS_CTL) -ljansson

$(CONF_BINARY): xdp_lb_conf.c xdp_lb_common.h
	$(CC) $(CFLAGS_CTL) xdp_lb_conf.c -o $@ $(LDLIBS_CTL)

clean:
	rm -f $(BPF_OBJECTS) $(CTL_BINARY) $(CONF_BINARY)

.PHONY: all clean

# AWFD (load_aware/DESIGN.md)
AWFD_BINARIES := xdp_lb_awfd xdp_lb_agent load_aware/xdp_lb_awfd_check

awfd: xdp_lb.o $(AWFD_BINARIES)

xdp_lb_awfd: xdp_lb_awfd.c xdp_lb_common.h
	$(CC) $(CFLAGS_CTL) xdp_lb_awfd.c -o $@ $(LDLIBS_CTL)

xdp_lb_agent: xdp_lb_agent.c xdp_lb_common.h
	$(CC) $(CFLAGS_CTL) xdp_lb_agent.c -o $@

# The check compiles the daemon in, so it is rebuilt when the daemon changes.
load_aware/xdp_lb_awfd_check: load_aware/xdp_lb_awfd_check.c xdp_lb_awfd.c xdp_lb_common.h
	$(CC) $(CFLAGS_CTL) -I. $< -o $@ $(LDLIBS_CTL)

clean-awfd:
	rm -f $(AWFD_BINARIES)

.PHONY: awfd clean-awfd
