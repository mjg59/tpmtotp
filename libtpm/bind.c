/********************************************************************************/
/*										*/
/*			     	TPM Bind/Unbind routines			*/
/*			     Written by J. Kravitz				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: bind.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <tpmkeys.h>
#include <tpm_constants.h>
#include <oiaposap.h>
#include <tpmfunc.h>
#include <hmac.h>
#include <openssl/rsa.h>

   
/****************************************************************************/
/*                                                                          */
/* Unbind a data object                                                     */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to bind the data                 */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it is assumed that the key needs no authorization     */
/* data      is a pointer to the data to be unbound                         */
/* datalen   is the length of the data to be unbound (max 256?)             */
/* blob      is a pointer to an area to received the unbound data           */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the unbound data                                            */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_UnBind(uint32_t keyhandle,
                    unsigned char *keyauth,
                    unsigned char *data, uint32_t datalen,
                    unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret = 0;
	STACK_TPM_BUFFER(tpmdata)
	session sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_UnBind);
	uint32_t datsize = htonl(datalen);
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t keytype;
	uint32_t infosize;

	/* check input arguments */
	if (data == NULL || blob == NULL) return ERR_NULL_ARG;
	if (keyhandle == 0x40000000) keytype = TPM_ET_SRK;
	else                         keytype = TPM_ET_KEYHANDLE;
	
	ret = needKeysRoom(keyhandle, 0 , 0, 0);
	if (ret != 0) {
		return ret;
	}
	
	if (keyauth != NULL)  /* key needs authorization */ {
		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,keyauth,keytype,keyhandle);
		if (ret != 0) {
			return ret;
		}
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* move Network byte order data to variables for HMAC calculation */
		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   TPM_U32_SIZE,&datsize,
		                   datalen,data,0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C2 T l l @ L % o %",&tpmdata,
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
		ret = TPM_Transmit(&tpmdata,"UnBind");
		TSS_SessionClose(&sess);

		if (ret != 0) {
			return ret;
		}
		/* calculate the size of the returned Blob */
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &infosize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     TPM_U32_SIZE,TPM_DATA_OFFSET,
		                     infosize,TPM_DATA_OFFSET + TPM_U32_SIZE,
		                     0,0);
		if (ret != 0) {
			return ret;
		}
		/* copy the returned blob to caller */
		memcpy(blob,
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
		       infosize);
		*bloblen = infosize;
	} else { /* key needs NO authorization */
		/* move Network byte order data to variables for HMAC calculation */

		/* build the request buffer */
		ret = TSS_buildbuff("00 C1 T l l @",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 datalen,data);
		if ((ret & ERR_MASK) != 0) 
			return ret;
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"UnBind");
		if (ret != 0) 
			return ret;
		/* calculate the size of the returned Blob */
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET,&infosize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* copy the returned blob to caller */
		memcpy(blob,
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
		       infosize);
		*bloblen = infosize;
	}
	return ret;
}
             
/****************************************************************************/
/*                                                                          */
/* bind a data object                                                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* key       is a pointer to a OpenSSL RSA public key                       */
/* data      is a pointer to the data to be bound                           */
/* datalen   is the length of the data to be bound   (max 256)              */
/* blob      is a pointer to an area to receive the bound data              */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the bound data                                              */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_Bind(RSA *key,
                  const struct tpm_buffer *data,
                  struct tpm_buffer *blob)
{
	uint32_t ret;
	unsigned char * blob2 = NULL;
	int size = RSA_size(key);
	unsigned char tcpa[] = "TCPA";
	
	blob2 = malloc(size);
	if (NULL == blob2) {
		return ERR_MEM_ERR;
	}
	/* check input arguments */
	if (key == NULL || data == NULL || blob == NULL) 
		return ERR_NULL_ARG;

	ret = RSA_padding_add_PKCS1_OAEP(blob2,size,data->buffer,data->used,tcpa,4);
	if (ret != 1) {
		 free(blob2);
		 return ERR_CRYPT_ERR;
	}
	ret = RSA_public_encrypt(size,blob2,blob->buffer,key,RSA_NO_PADDING);
	free(blob2);
	if ((int)ret == -1) 
		 return ERR_CRYPT_ERR;
	blob->used = ret;
	return 0;
}

uint32_t TSS_BindPKCSv15(RSA *key,
                         const struct tpm_buffer *data,
                         struct tpm_buffer *blob)
{
	uint32_t ret;
	unsigned char * blob2 = NULL;
	int size = RSA_size(key);
	
	blob2 = malloc(size);
	if (NULL == blob2) {
		return ERR_MEM_ERR;
	}
	/* check input arguments */
	if (key == NULL || data == NULL || blob == NULL) 
		return ERR_NULL_ARG;

	ret = RSA_padding_add_PKCS1_type_2(blob2,size,data->buffer,data->used);
	if (ret != 1) {
		 free(blob2);
		 return ERR_CRYPT_ERR;
	}
	ret = RSA_public_encrypt(size,blob2,blob->buffer,key,RSA_NO_PADDING);
	free(blob2);
	if ((int)ret == -1) {
		 return ERR_CRYPT_ERR;
	}
	blob->used = ret;
	return 0;
}
