/********************************************************************************/
/*										*/
/*			     	TPM Session Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: oiaposap.h 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#ifndef OIAPOSAP_H
#define OIAPOSAP_H
#include <tpm.h>
#include <tpm_structures.h>

typedef struct osapsess
   {
   uint32_t      handle;
   unsigned char enonce[TPM_NONCE_SIZE];
   unsigned char enonceOSAP[TPM_NONCE_SIZE];
   unsigned char ononceOSAP[TPM_NONCE_SIZE];
   unsigned char ssecret[TPM_HASH_SIZE];
   unsigned char ononce[TPM_NONCE_SIZE];
   uint16_t      etype;
   } osapsess;

typedef struct dsapsess
   {
   uint32_t      handle;
   unsigned char enonce[TPM_NONCE_SIZE];
   unsigned char enonceDSAP[TPM_NONCE_SIZE];
   unsigned char ononceDSAP[TPM_NONCE_SIZE];
   unsigned char ssecret[TPM_HASH_SIZE];
   unsigned char ononce[TPM_NONCE_SIZE];
   uint16_t      etype;
   } dsapsess;

typedef struct oiapsess
{
	uint32_t      handle;
	unsigned char enonce[TPM_NONCE_SIZE];
} oiapsess;

typedef struct transess
{
	uint32_t      handle;
	unsigned char enonce[TPM_NONCE_SIZE];
} transess;

typedef struct session
{
	uint32_t sess_type;   // see below
	union {
		oiapsess        oiap;
		osapsess        osap;
		dsapsess        dsap;
		transess        tran;
	} type;
	unsigned char authdata[TPM_AUTHDATA_SIZE];
} session;


#define  SESSION_OIAP   1
#define  SESSION_OSAP   2
#define  SESSION_DSAP   4
#define  SESSION_TRAN   8
#define  SESSION_DAA   16
   
uint32_t  TSS_HANDclose(uint32_t handle, TPM_RESOURCE_TYPE);
uint32_t  TSS_OIAPopen(uint32_t *handle, unsigned char *enonce);
uint32_t  TSS_OIAPclose(uint32_t handle);
uint32_t  TSS_OSAPopen(osapsess *sess,const unsigned char *key, uint16_t etype, uint32_t evalue);
uint32_t  TSS_OSAPclose(osapsess *sess);
uint32_t  TSS_DSAPopen(dsapsess *sess, 
                       unsigned char *key, 
                       uint16_t etype, 
                       uint32_t keyhandle, 
                       unsigned char * evalue, uint32_t evalueSize);
uint32_t TSS_DSAPclose(dsapsess *sess);

uint32_t TSS_SessionOpen(uint32_t allowed_type,
                         session * sess,
                         unsigned char *passHash, uint16_t etype, uint32_t evalue);
uint32_t TSS_SessionClose(session * sess);
uint32_t TSS_Session_CreateTransport(session *sess,
                                     unsigned char *transAuth,
                                     uint32_t transHandle,
                                     unsigned char *transNonce);
unsigned char * TSS_Session_GetAuth(session * sess);
unsigned char * TSS_Session_GetENonce(session * sess);
void TSS_Session_SetENonce(session * sess, const unsigned char *enonce);
uint32_t TSS_Session_GetHandle(session * sess);

#endif
