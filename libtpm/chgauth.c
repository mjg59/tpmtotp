/********************************************************************************/
/*										*/
/*			     	TPM Change Auth routines			*/
/*			     Written by J. Kravitz				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: chgauth.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <tpm.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tpmkeys.h>

#include <tpmfunc.h>		/* kgold */

/****************************************************************************/
/*                                                                          */
/* Change the Authorization for a Key Object                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the parent key                                */
/*           0x40000000 for the SRK                                         */
/* parauth   is the     authorization data (password) for the parent key    */
/* keyauth   is the old authorization data (password) for the key           */
/* newauth   is the new authorization data (password) for the key           */
/*           all authorization values must be 20 bytes long                 */
/* key       is a pointer to a key data structure                           */
/*                                                                          */
/****************************************************************************/
uint32_t
TPM_ChangeKeyAuth(uint32_t keyhandle,
	          unsigned char *parauth,
	          unsigned char *keyauth, unsigned char *newauth, keydata * key)
{
	uint32_t ret;

	STACK_TPM_BUFFER(tpmdata)
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char nonceodd2[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint16_t protocol;
	uint16_t entitytype;
	uint32_t keysize;
	uint32_t keyhndl;
	uint16_t keytype;
	uint32_t reslen;
	session sess, sess2;

	/* check input arguments */
	if (parauth == NULL || keyauth == NULL || newauth == NULL ||
	    key == NULL)
		return ERR_NULL_ARG;
	if (keyhandle == 0x40000000)
		keytype = 0x0004;
	else
		keytype = 0x0001;

	ret = needKeysRoom(keyhandle, 0 , 0, 0);
	if (ret != 0) {
		return ret;
	}

	/* open OSAP session for parent key auth */
	ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP,
	                      &sess,
	                      parauth, keytype, keyhandle);
	if (ret != 0)
		return ret;
	/* open OIAP session for existing key auth */
	ret = TSS_SessionOpen(SESSION_OIAP,
	                      &sess2,
	                      keyauth, 0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* calculate encrypted authorization value for OSAP session */
	TPM_CreateEncAuth(&sess, newauth, encauth, 0);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	TSS_gennonce(nonceodd2);
	/* move Network byte order data to variables for HMAC calculation */
	ordinal = htonl(TPM_ORD_ChangeAuth);
	protocol = htons(TPM_PID_ADCP);
	entitytype = htons(0x0005);
	keysize = htonl(key->encData.size);
	keyhndl = htonl(keyhandle);
	c = 0;
	/* calculate OSAP authorization HMAC value */
	ret = TSS_authhmac(authdata1, TSS_Session_GetAuth(&sess), TPM_NONCE_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c, 
			   TPM_U32_SIZE, &ordinal,
			   TPM_U16_SIZE, &protocol, 
			   TPM_HASH_SIZE, encauth,
			   TPM_U16_SIZE, &entitytype, 
			   TPM_U32_SIZE, &keysize,
			   key->encData.size, key->encData.buffer, 
			   0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* calculate OIAP authorization HMAC value */
	ret = TSS_authhmac(authdata2, TSS_Session_GetAuth(&sess2), TPM_NONCE_SIZE, TSS_Session_GetENonce(&sess2),
			   nonceodd2, c, 
			   TPM_U32_SIZE, &ordinal, 
			   TPM_U16_SIZE, &protocol, 
			   TPM_HASH_SIZE, encauth, 
			   TPM_U16_SIZE, &entitytype, 
			   TPM_U32_SIZE, &keysize, 
			   key->encData.size, key->encData.buffer, 
			   0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 C3 T l l s % s @ L % o % L % o %", &tpmdata,
			             ordinal,
			               keyhndl,
			                 protocol,
			                   TPM_HASH_SIZE, encauth,
			                     entitytype,
			                       key->encData.size, key->encData.buffer,
			                         TSS_Session_GetHandle(&sess),
			                           TPM_NONCE_SIZE, nonceodd,
			                             c,
			                               TPM_HASH_SIZE, authdata1,
			                                 TSS_Session_GetHandle(&sess2),
			                                   TPM_NONCE_SIZE, nonceodd2,
			                                     c, 
			                                       TPM_HASH_SIZE, authdata2);

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "ChangeAuth - AUTH2");
	TSS_SessionClose(&sess);
	TSS_SessionClose(&sess2);

	if (ret != 0) {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &reslen);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac2(&tpmdata, ordinal, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, 
			     nonceodd2,
			     TSS_Session_GetAuth(&sess2), TPM_HASH_SIZE,
			     TPM_U32_SIZE, TPM_DATA_OFFSET,
			     reslen, TPM_DATA_OFFSET + TPM_U32_SIZE,
			     0, 0);
	if (ret != 0)
		return ret;
	/* copy updated key blob back to caller */
	memcpy(key->encData.buffer,
	       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE], reslen);
	return 0;
}


uint32_t
TPM_ChangeAuth(uint32_t keyhandle,
	       unsigned char *parauth,
	       unsigned char *keyauth, unsigned char *newauth, 
	       unsigned short etype,
	       unsigned char *encdata, uint32_t encdatalen)
{
	uint32_t ret;

	STACK_TPM_BUFFER(tpmdata)
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char nonceodd2[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint16_t protocol;
	uint16_t entitytype;
	uint32_t keyhndl;
	uint16_t keytype;
	uint32_t reslen;
	session sess, sess2;
	uint32_t encdatalen_no = htonl(encdatalen);

	/* check input arguments */
	if (parauth == NULL || keyauth == NULL || newauth == NULL ||
	    encdata == NULL)
		return ERR_NULL_ARG;
	if (keyhandle == 0x40000000)
		keytype = 0x0004;
	else
		keytype = 0x0001;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	/* open OSAP session for parent key auth */
	ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP,
	                      &sess,
	                      parauth, keytype, keyhandle);
	if (ret != 0)
		return ret;
	/* open OIAP session for existing key auth */
	ret = TSS_SessionOpen(SESSION_OIAP,
	                      &sess2,
	                      keyauth, 0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* calculate encrypted authorization value for OSAP session */
	TPM_CreateEncAuth(&sess, newauth, encauth, 0);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	TSS_gennonce(nonceodd2);

	/* move Network byte order data to variables for HMAC calculation */
	ordinal = htonl(TPM_ORD_ChangeAuth);
	protocol = htons(TPM_PID_ADCP);
	entitytype = htons(etype);
	keyhndl = htonl(keyhandle);
	c = 0;
	/* calculate OSAP authorization HMAC value */

	ret = TSS_authhmac(authdata1, TSS_Session_GetAuth(&sess), TPM_NONCE_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c, 
			   TPM_U32_SIZE, &ordinal,
			   TPM_U16_SIZE, &protocol, 
			   TPM_HASH_SIZE, encauth,
			   TPM_U16_SIZE, &entitytype, 
			   TPM_U32_SIZE, &encdatalen_no,
			   encdatalen, encdata,
			   0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* calculate OIAP authorization HMAC value */
	ret = TSS_authhmac(authdata2, TSS_Session_GetAuth(&sess2), TPM_NONCE_SIZE, TSS_Session_GetENonce(&sess2),
			   nonceodd2, c, 
			   TPM_U32_SIZE, &ordinal, 
			   TPM_U16_SIZE, &protocol, 
			   TPM_HASH_SIZE, encauth, 
			   TPM_U16_SIZE, &entitytype, 
			   TPM_U32_SIZE, &encdatalen_no, 
			   encdatalen, encdata, 
			   0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 C3 T l l s % s @ L % o % L % o %", &tpmdata,
			             ordinal,
			               keyhndl,
			                 protocol,
			                   TPM_HASH_SIZE, encauth,
			                     entitytype,
			                       encdatalen, encdata,
			                         TSS_Session_GetHandle(&sess),
			                           TPM_NONCE_SIZE, nonceodd,
			                             c,
			                               TPM_HASH_SIZE, authdata1,
			                                 TSS_Session_GetHandle(&sess2),
			                                   TPM_NONCE_SIZE, nonceodd2,
			                                     c, 
			                                       TPM_HASH_SIZE, authdata2);

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "ChangeAuth - AUTH2");
	TSS_SessionClose(&sess);
	TSS_SessionClose(&sess2);

	if (ret != 0) {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &reslen);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac2(&tpmdata, ordinal, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, 
			     nonceodd2, 
			     TSS_Session_GetAuth(&sess2), TPM_HASH_SIZE,
			     TPM_U32_SIZE, TPM_DATA_OFFSET,
			     reslen, TPM_DATA_OFFSET + TPM_U32_SIZE,
			     0, 0);
	if (ret != 0)
		return ret;
	/* copy updated key blob back to caller */
	memcpy(encdata,
	       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE], reslen);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Change the Authorization for the Storage Root Key                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   is the     authorization data (password) for the TPM Owner     */
/* newauth   is the new authorization data (password) for the SRK           */
/*           all authorization values must be 20 bytes long                 */
/*                                                                          */
/****************************************************************************/
uint32_t
TPM_ChangeSRKAuth(unsigned char *ownauth, unsigned char *newauth)
{
	uint32_t ret;

	STACK_TPM_BUFFER(tpmdata)
	session sess;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(0x10);
	uint16_t protocol = htons(0x0004);
	uint16_t entitytype = htons(0x0004);

	/* check input arguments */
	if (ownauth == NULL || newauth == NULL)
		return ERR_NULL_ARG;
	/* open OSAP session for owner auth */
	ret = TSS_SessionOpen(SESSION_OSAP, &sess, ownauth, 0x0002, 0);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value for OSAP session */
	TPM_CreateEncAuth(&sess, newauth, encauth ,0);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* calculate OSAP authorization HMAC value */
	ret = TSS_authhmac(authdata1, TSS_Session_GetAuth(&sess), TPM_NONCE_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c, TPM_U32_SIZE, &ordinal,
			   TPM_U16_SIZE, &protocol, TPM_HASH_SIZE, encauth,
			   TPM_U16_SIZE, &entitytype, 0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 C2 T l s % s L % o %", &tpmdata,
			    ordinal,
			    protocol,
			    TPM_HASH_SIZE, encauth,
			    entitytype,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata1);

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "ChangeSRKAuth - AUTH1");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac1(&tpmdata, ordinal, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, 0, 0);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Change the Authorization for the TPM Owner                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   is the old authorization data (password) for the TPM Owner     */
/* newauth   is the new authorization data (password) for the TPM Owner     */
/*           all authorization values must be 20 bytes long                 */
/*                                                                          */
/****************************************************************************/
uint32_t
TPM_ChangeOwnAuth(unsigned char *ownauth, unsigned char *newauth)
{
	uint32_t ret;

	STACK_TPM_BUFFER(tpmdata)
	session sess;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(0x10);
	uint16_t protocol = htons(0x0004);
	uint16_t entitytype = htons(0x0002);

	/* check input arguments */
	if (ownauth == NULL || newauth == NULL)
		return ERR_NULL_ARG;
	/* open OSAP session for owner auth */
	ret = TSS_SessionOpen(SESSION_OSAP,&sess, ownauth, 0x0002, 0);

	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value for OSAP session */
	TPM_CreateEncAuth(&sess, newauth, encauth, 0);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* calculate OSAP authorization HMAC value */
	ret = TSS_authhmac(authdata1, TSS_Session_GetAuth(&sess), TPM_NONCE_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c, TPM_U32_SIZE, &ordinal,
			   TPM_U16_SIZE, &protocol, TPM_HASH_SIZE, encauth,
			   TPM_U16_SIZE, &entitytype, 0, 0);

	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}

	/* build the request buffer */
	ret = TSS_buildbuff("00 C2 T l s % s L % o %", &tpmdata,
			    ordinal,
			    protocol,
			    TPM_HASH_SIZE, encauth,
			    entitytype,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata1);

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "ChangeOwnAuth - AUTH1");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac1(&tpmdata, ordinal, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, 0, 0);
	return ret;
}
