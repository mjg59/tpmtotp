/********************************************************************************/
/*										*/
/*			     	TPM Signature Routines				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: signature.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <tpmfunc.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>


/****************************************************************************/
/*                                                                          */
/* Sign some data                                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key to sign with                          */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the key has no authorization req   */
/* data      is a pointer to the data to be signed                          */
/* datalen   is the length of the data being signed                         */
/* sig       is a pointer to an area to receive the signature (<=256 bytes) */
/* siglen    is a pointer to an integer to receive the signature length     */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Sign(uint32_t keyhandle, unsigned char *keyauth,
             unsigned char *data, uint32_t datalen, 
             unsigned char *sig, uint32_t *siglen) {
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_Sign);
	uint32_t keyhndl = htonl(keyhandle);
	uint32_t datasize = htonl(datalen);
	uint32_t sigsize;

	/* check input arguments */
	if (data == NULL || sig == NULL) return ERR_NULL_ARG;
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	if (keyauth != NULL)  /* key requires authorization */
	{
		session sess;
		/* 
		    generate odd nonce from data. This is
                    good, but for a test suite it should
                    be OK. I need to do this to be able to later on
                    verify the INFO type of signature.
                */
		TSS_sha1(data, datalen, nonceodd);
		
		/* Open OIAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP|SESSION_DSAP,
		                      &sess,
		                      keyauth, TPM_ET_KEYHANDLE, keyhandle);
		if (ret != 0)
			return ret;

		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   TPM_U32_SIZE,&datasize,
		                   datalen,data,
		                   0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l @ L % o %",&tpmdata,
		                    ordinal,
		                    keyhndl,
		                    datalen,data,
		                    TSS_Session_GetHandle(&sess),
		                    TPM_NONCE_SIZE,nonceodd,
		                    c,
		                    TPM_HASH_SIZE,pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Sign");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &sigsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     TPM_U32_SIZE,TPM_DATA_OFFSET,
		                     sigsize,TPM_DATA_OFFSET+TPM_U32_SIZE,
		                     0,0);
		if (ret != 0) 
			return ret;
		memcpy(sig,
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
		       sigsize);
		*siglen = sigsize;
	} else /* key requires NO authorization */ {
		/* move Network byte order data to variables for hmac calculation */
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l @",&tpmdata,
		                    ordinal,
		                    keyhndl,
		                    datalen,data);
		if ((ret & ERR_MASK) != 0) 
			return ret;
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Sign");
		if (ret != 0) 
			return ret;
		ret     = tpm_buffer_load32(&tpmdata,
		                            TPM_DATA_OFFSET,
		                            &sigsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		memcpy(sig,
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
		       sigsize);
		*siglen = sigsize;
	}
	return 0;
}
