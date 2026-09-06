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

all: $(BPF_OBJECTS) $(CTL_BINARY)

xdp_lb.o: xdp_lb.c xdp_lb_common.h
	$(CLANG) $(CFLAGS_BPF) -c xdp_lb.c -o $@

xdp_lb_deencap.o: xdp_lb_deencap.c
	$(CLANG) $(CFLAGS_BPF) -c xdp_lb_deencap.c -o $@

$(CTL_BINARY): xdp_lb_ctl.c xdp_lb_common.h
	$(CC) $(CFLAGS_CTL) xdp_lb_ctl.c -o $@ $(LDLIBS_CTL)

clean:
	rm -f $(BPF_OBJECTS) $(CTL_BINARY)

.PHONY: all clean
