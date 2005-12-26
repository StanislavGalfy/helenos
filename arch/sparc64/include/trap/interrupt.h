/*
 * Copyright (C) 2005 Jakub Jermar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * This file contains interrupt vector trap handler.
 */

#ifndef __sparc64_INTERRUPT_H__
#define __sparc64_INTERRUPT_H__

#include <arch/trap/trap_table.h>

#define TT_INTERRUPT_LEVEL_1			0x41
#define TT_INTERRUPT_LEVEL_2			0x42
#define TT_INTERRUPT_LEVEL_3			0x43
#define TT_INTERRUPT_LEVEL_4			0x44
#define TT_INTERRUPT_LEVEL_5			0x45
#define TT_INTERRUPT_LEVEL_6			0x46
#define TT_INTERRUPT_LEVEL_7			0x47
#define TT_INTERRUPT_LEVEL_8			0x48
#define TT_INTERRUPT_LEVEL_9			0x49
#define TT_INTERRUPT_LEVEL_10			0x4a
#define TT_INTERRUPT_LEVEL_11			0x4b
#define TT_INTERRUPT_LEVEL_12			0x4c
#define TT_INTERRUPT_LEVEL_13			0x4d
#define TT_INTERRUPT_LEVEL_14			0x4e
#define TT_INTERRUPT_LEVEL_15			0x4f

#define TT_INTERRUPT_VECTOR_TRAP		0x60

#define INTERRUPT_LEVEL_N_HANDLER_SIZE		TRAP_TABLE_ENTRY_SIZE
#define INTERRUPT_VECTOR_TRAP_HANDLER_SIZE	TRAP_TABLE_ENTRY_SIZE

#ifdef __ASM__
.macro INTERRUPT_LEVEL_N_HANDLER n
	save %sp, -128, %sp
	mov \n - 1, %o0
	call exc_dispatch
	mov %fp, %o1
	restore
	retry
.endm

.macro INTERRUPT_VECTOR_TRAP_HANDLER
	retry
.endm
#endif /* __ASM__ */

#endif
