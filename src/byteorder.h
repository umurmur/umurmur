/* Copyright (C) 2014, Felix Morgner <felix.morgner@gmail.com>
   Copyright (C) 2009-2014, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2014, Thorvald Natvig <thorvald@natvig.com>

   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   - Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
   - Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
   - Neither the name of the Developers nor the names of its contributors may
     be used to endorse or promote products derived from this software without
     specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef BYTEORDER_H_
#define BYTEORDER_H_

#include <stdint.h>

#if defined(NETBSD) || defined(FREEBSD) || defined(OPENBSD) || defined(MACOSX)
#include <machine/endian.h>
#if BYTE_ORDER == BIG_ENDIAN
#define BYTE_ORDER_BIG_ENDIAN
#endif // BYTE_ORDER == BIG_ENDIAN
#elif defined(LINUX)
#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define BYTE_ORDER_BIG_ENDIAN
#endif // __BYTE_ORDER == __BIG_ENDIAN
#endif // defined(NETBSD) || defined(FREEBSD) || defined(OPENBSD)

#if defined(__LP64__)
#define BLOCKSIZE 2
#define SHIFTBITS 63
typedef uint64_t subblock;
#if defined(BYTE_ORDER_BIG_ENDIAN)
#define SWAPPED(x) (x)
#elif defined( __x86_64__)
#define SWAPPED(x) ({register uint64_t __out, __in = (x); __asm__("bswap %q0" : "=r"(__out) : "0"(__in)); __out;})
#else
#include <byteswap.h>
#define SWAPPED(x) bswap_64(x)
#endif // defined(BYTE_ORDER_BIG_ENDIAN)
#else
#define BLOCKSIZE 4
#define SHIFTBITS 31
typedef uint32_t subblock;
#define SWAPPED(x) htonl(x)
#endif // defined(__LP64__)

#define HIGHBIT (1<<SHIFTBITS);

#endif // BYTEORDER_H_
