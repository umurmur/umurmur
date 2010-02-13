/* Copyright (C) 2009-2010, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2010, Thorvald Natvig <thorvald@natvig.com>

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
#ifndef CRYPTSTATE_H_34564356
#define CRYPTSTATE_H_34564356

#ifdef USE_POLARSSL
#include <polarssl/havege.h>
#include <polarssl/aes.h>
#define AES_BLOCK_SIZE 16
#else
#include <openssl/rand.h>
#include <openssl/aes.h>
#endif

#include <stdint.h>
#include "timer.h"
#include "types.h"

typedef struct CryptState {
	uint8_t raw_key[AES_BLOCK_SIZE];
	uint8_t encrypt_iv[AES_BLOCK_SIZE];
	uint8_t decrypt_iv[AES_BLOCK_SIZE];
	uint8_t decrypt_history[0x100];
	
	unsigned int uiGood;
	unsigned int uiLate;
	unsigned int uiLost;
	unsigned int uiResync;
	
	unsigned int uiRemoteGood;
	unsigned int uiRemoteLate;
	unsigned int uiRemoteLost;
	unsigned int uiRemoteResync;
#ifndef USE_POLARSSL
	AES_KEY	encrypt_key;
	AES_KEY decrypt_key;
#else
	aes_context aes_enc;
	aes_context aes_dec;
#endif
	etimer_t tLastGood;
	etimer_t tLastRequest;
	bool_t bInit;	
} cryptState_t;

void CryptState_init(cryptState_t *cs);
bool_t CryptState_isValid(cryptState_t *cs);
void CryptState_genKey(cryptState_t *cs);
void CryptState_setKey(cryptState_t *cs, const unsigned char *rkey, const unsigned char *eiv, const unsigned char *div);
void CryptState_setDecryptIV(cryptState_t *cs, const unsigned char *iv);

bool_t CryptState_decrypt(cryptState_t *cs, const unsigned char *source, unsigned char *dst, unsigned int crypted_length);
void CryptState_encrypt(cryptState_t *cs, const unsigned char *source, unsigned char *dst, unsigned int plain_length);

#endif
