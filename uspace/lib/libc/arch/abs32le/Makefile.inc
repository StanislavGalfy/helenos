#
# Copyright (c) 2010 Martin Decky
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# - Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# - The name of the author may not be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

## Toolchain configuration
#

ifeq ($(COMPILER),gcc_cross)
	TOOLCHAIN_DIR = $(CROSS_PREFIX)/$(CROSS_TARGET)/bin
	
	ifeq ($(CROSS_TARGET),arm32)
		TARGET = arm-linux-gnu
	endif
	
	ifeq ($(CROSS_TARGET),ia32)
		TARGET = i686-pc-linux-gnu
	endif
	
	ifeq ($(CROSS_TARGET),mips32)
		TARGET = mipsel-linux-gnu
	endif
endif

ifeq ($(COMPILER),clang)
	CLANG_ARCH = i386
endif

ARCH_SOURCES = \
	arch/$(UARCH)/src/entry.c \
	arch/$(UARCH)/src/thread_entry.c \
	arch/$(UARCH)/src/fibril.c \
	arch/$(UARCH)/src/tls.c \
	arch/$(UARCH)/src/syscall.c \
	arch/$(UARCH)/src/stacktrace.c

ENDIANESS = LE