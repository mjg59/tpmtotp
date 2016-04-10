/********************************************************************************/
/*										*/
/*			     	TPM Utilities					*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil.h 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef TPMUTIL_H
#define TPMUTIL_H

#include <stdint.h>

#include <openssl/aes.h>

#include <tpm_structures.h>

#include <oiaposap.h>

#ifdef MIN
#undef MIN
#endif

#define MIN(x,y) (x) < (y) ? (x) : (y)

#define TPM_COUNTER_VALUE_SIZE 10

#define TPM_MAX_TRANSPORTS 10

/* AES requires data lengths that are a multiple of the block size */
#define TPM_AES_BITS 128
/* The AES block size is always 16 bytes */
#define TPM_AES_BLOCK_SIZE 16


struct tpm_buffer;

uint32_t TSS_getsize(unsigned char *rsp);
int      TSS_gennonce(unsigned char *nonce);
int      TSS_buildbuff(char *format,struct tpm_buffer *, ...);
int      TSS_parsebuff(char *format,const struct tpm_buffer *, uint32_t offset, ...);
uint32_t TPM_Transmit(struct tpm_buffer *,const char *msg);
uint32_t TPM_Transmit_NoTransport(struct tpm_buffer *,const char *msg);
uint32_t TPM_Send(struct tpm_buffer *,const char *);
int      TPM_setlog(int flag);
void     TSS_sha1(void *input, unsigned int len, unsigned char *output);
uint32_t TSS_SHAFile(const char *filename, unsigned char *hash);
void     showBuff(unsigned char* buff, char* string);

uint32_t TPM_GetDelegationBlob(uint32_t etype, 
                               uint32_t keyhandle, 
                               unsigned char *passHash,
                               unsigned char *buffer, uint32_t *bufferSize);
uint32_t TPM_AddDelegationBlob(uint32_t etype, 
                               uint32_t keyhandle, 
                               unsigned char *oldPassHash,
                               unsigned char *newPassHash,
                               unsigned char *buffer, uint32_t bufferSize);
uint32_t TPM_ResetDelegation(void);


uint32_t _TPM_AuditInputstream(const struct tpm_buffer *req, int is_encrypted);
uint32_t _TPM_AuditOutputstream(const struct tpm_buffer *res, uint32_t ord,
                                int is_encrypted);
uint32_t _TPM_IsAuditedOrdinal(uint32_t ord, uint32_t *rc);
uint32_t TPM_SetAuditedOrdinal(uint32_t ord);
uint32_t TPM_ClearAuditedOrdinal(uint32_t ord);
uint32_t TPM_SetAuditingCounterValue(TPM_COUNTER_VALUE *cv);
uint32_t TPM_ResetAuditing(void);

uint32_t getNumHandles(uint32_t ord);
uint32_t getNumRespHandles(uint32_t ord);
#if 0
uint32_t TPM_OpenClientSocket(int *sock_fd);
uint32_t TPM_CloseClientSocket(int sock_fd);
uint32_t TPM_TransmitSocket(int sock_fd, struct tpm_buffer *tb);
uint32_t TPM_ReceiveSocket(int sock_fd, struct tpm_buffer *tb);
uint32_t TPM_ReceiveBytes(int sock_fd,
                          unsigned char *buffer,
                          size_t nbytes);
#endif

uint32_t tpm_buffer_load32 (const struct tpm_buffer *tb, uint32_t offset, uint32_t *val);
uint32_t tpm_buffer_load32N(const struct tpm_buffer *tb, uint32_t offset, uint32_t *val);
uint32_t tpm_buffer_load16 (const struct tpm_buffer *tb, uint32_t offset, uint16_t *val);
uint32_t tpm_buffer_load16N(const struct tpm_buffer *tb, uint32_t offset, uint16_t *val);
uint32_t tpm_buffer_store32(struct tpm_buffer *tb, uint32_t val);
uint32_t tpm_buffer_store(struct tpm_buffer *dest, struct tpm_buffer *src, uint32_t soff, uint32_t slen);

uint32_t parseHash(char *string, unsigned char *hash);
TPM_RESULT TPM_AES_ctr128_Encrypt(unsigned char *data_out,
				  const unsigned char *data_in,
				  unsigned long data_size,
				  const AES_KEY *aes_enc_key,
				  unsigned char ctr[TPM_AES_BLOCK_SIZE]);
TPM_RESULT TSS_MGF1(unsigned char       *mask,
                    uint32_t             maskLen,
                    const unsigned char *mgfSeed,
                    uint32_t             mgfSeedlen);
TPM_RESULT TSS_SHA1(TPM_DIGEST md, ...);


#if 0
void TPM_XOR(unsigned char *out,
	     const unsigned char *in1,
	     const unsigned char *in2,
	     size_t length);
#endif

int allowsTransport(uint32_t ord);

void _TPM_getTransportAlgIdEncScheme(TPM_ALGORITHM_ID *algId,
                                     TPM_ENC_SCHEME *encScheme);
void TPM_DetermineSessionEncryption(const session *, int *);

uint32_t needKeysRoom(uint32_t key1, uint32_t key2, uint32_t key3,
                      int room);
uint32_t needKeysRoom_Stacked(uint32_t key1, uint32_t *orig_key1);
uint32_t needKeysRoom_Stacked_Undo(uint32_t swapout_key, uint32_t swapin_key);


#endif
