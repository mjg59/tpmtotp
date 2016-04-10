/********************************************************************************/
/*										*/
/*			     	TPM SEAL/UNSEAL routines			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: seal.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <tpm_structures.h>
#include <tpmfunc.h>
#include <oiaposap.h>
#include <hmac.h>
#include <pcrs.h>

#define MAXPCRINFOLEN ( (TPM_HASH_SIZE * 2) + TPM_U16_SIZE + TPM_PCR_MASK_SIZE )
   
/****************************************************************************/
/*                                                                          */
/* Seal a data object with caller Specified PCR info                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* pcrinfo   is a pointer to a TPM_PCR_INFO structure containing            */
/*           a bit map of the PCR's to seal the data to, and a              */
/*           pair of TPM_COMPOSITE_HASH values for the PCR's                */
/* pcrinfosize is the length of the pcrinfo structure                       */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long                */
/* data      is a pointer to the data to be sealed                          */
/* datalen   is the length of the data to be sealed (max 256?)              */
/* blob      is a pointer to an area to received the sealed blob            */
/*           it should be long enough to receive the encrypted data         */
/*           which is 256 bytes, plus some overhead. 512 total recommended? */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the sealed blob                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Seal(uint32_t keyhandle,
                  unsigned char *pcrinfo, uint32_t pcrinfosize,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, uint32_t datalen,
                  unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret = 0;
	ALLOC_TPM_BUFFER(tpmdata, 0)
	session sess;
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char dummyauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_Seal);
	uint32_t pcrsize = htonl(pcrinfosize);
	uint32_t datsize = htonl(datalen);
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t keytype;
	unsigned char *passptr1;
	unsigned char *passptr2;
	uint32_t    sealinfosize;
	uint32_t    encdatasize;
	uint32_t    storedsize;

	if (NULL == tpmdata) {
		 return ERR_MEM_ERR;
	}
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	memset(dummyauth,0,sizeof dummyauth);
	/* check input arguments */
	if (data == NULL || 
	    blob == NULL) 
	    return ERR_NULL_ARG;
	if (pcrinfosize != 0 && 
	    pcrinfo == NULL) 
	    return ERR_NULL_ARG;
	if (keyhandle == 0x40000000) keytype = TPM_ET_SRK;
	else                         keytype = TPM_ET_KEYHANDLE;
	if (keyauth  == NULL) passptr1 = dummyauth;
	else                  passptr1 = keyauth;
	if (dataauth == NULL) passptr2 = dummyauth;
	else                  passptr2 = dataauth;

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,passptr1,keytype,keyhandle);
	if (ret != 0) {
		goto exit; 
	}
	/* calculate encrypted authorization value */
	TPM_CreateEncAuth(&sess,passptr2, encauth, 0);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* move Network byte order data to variables for hmac calculation */

	/* calculate authorization HMAC value */
	if (pcrinfosize == 0) {
		/* no pcr info specified */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   TPM_HASH_SIZE,encauth,
		                   TPM_U32_SIZE,&pcrsize,
		                   TPM_U32_SIZE,&datsize,
		                   datalen,data,0,0);
	} else {
		/* pcr info specified */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   TPM_HASH_SIZE,encauth,
		                   TPM_U32_SIZE,&pcrsize,
		                   pcrinfosize,pcrinfo,
		                   TPM_U32_SIZE,&datsize,
		                   datalen,data,0,0);
	}
	if (ret != 0) {
		TSS_SessionClose(&sess);
		goto exit;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 C2 T l l % @ @ L % o %",tpmdata,
	                             ordinal,
	                               keyhndl,
	                                 TPM_HASH_SIZE,encauth,
	                                   pcrinfosize,pcrinfo,
	                                     datalen,data,
	                                       TSS_Session_GetHandle(&sess),
	                                         TPM_NONCE_SIZE,nonceodd,
	                                           c,
	                                             TPM_HASH_SIZE,pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		goto exit;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata,"Seal - AUTH1");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		goto exit;
	}
	/* calculate the size of the returned Blob */
	ret = tpm_buffer_load32(tpmdata,TPM_DATA_OFFSET + TPM_U32_SIZE, &sealinfosize);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret  = tpm_buffer_load32(tpmdata,TPM_DATA_OFFSET + TPM_U32_SIZE+TPM_U32_SIZE+sealinfosize, &encdatasize);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	storedsize   = TPM_U32_SIZE + TPM_U32_SIZE + sealinfosize + TPM_U32_SIZE + encdatasize;
	/* check the HMAC in the response */
	ret = TSS_checkhmac1(tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     storedsize,TPM_DATA_OFFSET,
	                     0,0);
	if (ret != 0) {
		goto exit;
	}
	/* copy the returned blob to caller */
	memcpy(blob,&tpmdata->buffer[TPM_DATA_OFFSET],storedsize);
	*bloblen = storedsize;

exit:
	FREE_TPM_BUFFER(tpmdata);
	return ret;
}
             
/****************************************************************************/
/*                                                                          */
/* Seal a data object with current PCR information                          */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* pcrmap    is a 32 bit integer containing a bit map of the PCR register   */
/*           numbers to be used when sealing. e.g 0x0000001 specifies       */
/*           PCR 0. 0x00000003 specifies PCR's 0 and 1, etc.                */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long                */
/* data      is a pointer to the data to be sealed                          */
/* datalen   is the length of the data to be sealed (max 256?)              */
/* blob      is a pointer to an area to received the sealed blob            */
/*           it should be long enough to receive the encrypted data         */
/*           which is 256 bytes, plus some overhead. 512 total recommended? */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the sealed blob                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_SealCurrPCR(uint32_t keyhandle, uint32_t pcrmap,
                         unsigned char *keyauth,
                         unsigned char *dataauth,
                         unsigned char *data, uint32_t datalen,
                         unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret;
	unsigned char pcrinfo[MAXPCRINFOLEN];
	uint32_t pcrlen;
	
	ret = TSS_GenPCRInfo(pcrmap,pcrinfo,&pcrlen);
	if (ret != 0) 
		return ret;
	return TPM_Seal(keyhandle,
	                pcrinfo,pcrlen,
	                keyauth,dataauth,
	                data,datalen,
	                blob,bloblen);
}
   
/****************************************************************************/
/*                                                                          */
/* Unseal a data object                                                     */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           or NULL if no password is required                             */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           or NULL if no password is required                             */
/*           both authorization values must be 20 bytes long                */
/* blob      is a pointer to an area to containing the sealed blob          */
/* bloblen   is the length of the sealed blob                               */
/* rawdata   is a pointer to an area to receive the unsealed data (max 256?)*/
/* datalen   is a pointer to a int to receive the length of the data        */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Unseal(uint32_t keyhandle,
             unsigned char *keyauth,
             unsigned char *dataauth,
             unsigned char *blob, uint32_t bloblen,
             unsigned char *rawdata, uint32_t *datalen)
{
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char dummyauth[TPM_NONCE_SIZE];
	unsigned char *passptr2;
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_Unseal);
	uint32_t keyhndl = htonl(keyhandle);
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	session sess;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	TSS_gennonce(nonceodd);
	memset(dummyauth,0,sizeof dummyauth);
	/* check input arguments */
	if (rawdata == NULL || blob == NULL) return ERR_NULL_ARG;
	if (dataauth == NULL) passptr2 = dummyauth;
	else                  passptr2 = dataauth;
	if (keyauth != NULL) /* key password specified */ {
		session sess2;
		unsigned char nonceodd2[TPM_NONCE_SIZE];
		TSS_gennonce(nonceodd2);

		/* open TWO OIAP sessions, one for the Key and one for the Data */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,
		                      &sess,
		                      keyauth, TPM_ET_KEYHANDLE, keyhandle);
		if (ret != 0) 
			return ret;

		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess2,
		                      passptr2, 0, 0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* calculate KEY authorization HMAC value */
		ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_NONCE_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   bloblen,blob,
		                   0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);

			return ret;
		}
		/* calculate DATA authorization HMAC value */
		ret = TSS_authhmac(authdata2,TSS_Session_GetAuth(&sess2),TPM_NONCE_SIZE,/*enonce2*/TSS_Session_GetENonce(&sess2),nonceodd2,c,
		                   TPM_U32_SIZE,&ordinal,
		                   bloblen,blob,
		                   0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C3 T l l % L % o % L % o %",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 bloblen,blob,
		                                   TSS_Session_GetHandle(&sess),
		                                     TPM_NONCE_SIZE,nonceodd,
		                                       c,
		                                         TPM_HASH_SIZE,authdata1,
		                                           TSS_Session_GetHandle(&sess2),
		                                             TPM_NONCE_SIZE,nonceodd2,
		                                               c,
		                                                 TPM_HASH_SIZE,authdata2);

		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Unseal - AUTH2");
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);

		if (ret != 0) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET,datalen);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* check HMAC in response */
		ret = TSS_checkhmac2(&tpmdata,ordinal,nonceodd,
		                     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     nonceodd2,
		                     TSS_Session_GetAuth(&sess2),TPM_HASH_SIZE,
		                     TPM_U32_SIZE,TPM_DATA_OFFSET,
		                     *datalen,TPM_DATA_OFFSET+TPM_U32_SIZE,
		                     0,0);
	   } else /* no key password */ {
		/* open ONE OIAP session, for the Data */
		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess,
		                      passptr2, 0, 0);
		if (ret != 0) 
			return ret;
		/* calculate DATA authorization HMAC value */
		ret = TSS_authhmac(authdata2,/*passptr2*/TSS_Session_GetAuth(&sess),TPM_NONCE_SIZE,/*enonce2*/TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   bloblen,blob,0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C2 T l l % L % o %",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 bloblen,blob,
		                                   TSS_Session_GetHandle(&sess),
		                                     TPM_NONCE_SIZE,nonceodd,
		                                       c,
		                                         TPM_HASH_SIZE,authdata2);

		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Unseal - AUTH1");

		TSS_SessionClose(&sess);

		if (ret != 0) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, datalen);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* check HMAC in response */
		ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,
		                     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     TPM_U32_SIZE,TPM_DATA_OFFSET,
		                     *datalen,TPM_DATA_OFFSET+TPM_U32_SIZE,
		                     0,0);
	}
	if (ret != 0) {
		return ret;
	}
	/* copy decrypted data back to caller */
	memcpy(rawdata,
	       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
	       *datalen);
	return ret;
}

static uint32_t MGF1_encrypt(unsigned char *data, uint32_t datalen,
                             session *sess,
                             unsigned char *nonceodd,
                             unsigned char *output)
{
	uint32_t seedsize;
	struct tpm_buffer *seed;
	uint32_t ret = 0;
	uint32_t i;

	seed = TSS_AllocTPMBuffer(TPM_NONCE_SIZE+TPM_NONCE_SIZE+sizeof("XOR")-1+TPM_HASH_SIZE);
	if (NULL == seed) {
		return ERR_MEM_ERR;
	}

	ret = TSS_buildbuff("% % % %", seed,
	                     TPM_NONCE_SIZE, TSS_Session_GetENonce(sess),
	                       TPM_NONCE_SIZE, nonceodd,
	                         sizeof("XOR")-1, "XOR",
	                           TPM_HASH_SIZE, TSS_Session_GetAuth(sess));
	if ((ret & ERR_MASK) != 0) {
		goto exit;
	}
	seedsize = ret;
	TSS_MGF1(output,
		 datalen,
		 seed->buffer,
		 seedsize);

	for (i = 0; i < datalen; i++) {
		output[i] = output[i] ^ data[i];
	}

exit:
	TSS_FreeTPMBuffer(seed);
	return 0;
}


static uint32_t AES_CTR_crypt(unsigned char *data, uint32_t datalen,
                              const session *sess, 
                              unsigned char *nonceodd,
                              unsigned char *output)
{
	uint32_t ret = 0;
	AES_KEY aeskey;
	unsigned char ivec[TPM_HASH_SIZE];
	unsigned char work[TPM_NONCE_SIZE * 2];
	int rc;
		
	rc = AES_set_encrypt_key(TSS_Session_GetAuth((session *)sess),
	                         TPM_AES_BITS,
	                         &aeskey);
        (void)rc;

	memcpy(&work[00], TSS_Session_GetENonce((session *)sess), TPM_NONCE_SIZE);
	memcpy(&work[TPM_NONCE_SIZE],
	                  nonceodd, TPM_NONCE_SIZE);
	TSS_sha1(work, sizeof(work), ivec);

	TPM_AES_ctr128_Encrypt(output,
			       data, 
			       datalen,
			       &aeskey,
			       ivec);

	return ret;
}             

static uint32_t Sealx_DataEncrypt(unsigned char *data, uint32_t datalen,
                                  session *sess,
                                  unsigned char *nonceodd,
                                  unsigned char *output)
{
	uint32_t ret = 0;
	int use_xor = 0;
	
	TPM_DetermineSessionEncryption(sess, &use_xor);
	if (use_xor) {
		ret = MGF1_encrypt(data, datalen,
		                   sess,
		                   nonceodd,
		                   output);
	} else {
		ret = AES_CTR_crypt(data, datalen, 
		                    sess,
		                    nonceodd,
		                    output);
	}
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Seal an encrypted data object with caller Specified PCR info             */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* pcrinfo   is a pointer to a TPM_PCR_INFO structure containing            */
/*           a bit map of the PCR's to seal the data to, and a              */
/*           pair of TPM_COMPOSITE_HASH values for the PCR's                */
/* pcrinfosize is the length of the pcrinfo structure                       */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long                */
/* data      is a pointer to the data to be sealed                          */
/* datalen   is the length of the data to be sealed (max 256?)              */
/* blob      is a pointer to an area to received the sealed blob            */
/*           it should be long enough to receive the encrypted data         */
/*           which is 256 bytes, plus some overhead. 512 total recommended? */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the sealed blob                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Sealx(uint32_t keyhandle,
                   TPM_PCR_INFO_LONG *pil,
                   unsigned char *keyauth,
                   unsigned char *dataauth,
                   unsigned char *data, uint32_t datalen,
                   unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret;
	ALLOC_TPM_BUFFER(tpmdata, 0)
	session sess;
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char dummyauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_Sealx);
	uint32_t datsize = htonl(datalen);
	uint32_t keyhndl_no = htonl(keyhandle);
	uint32_t pcrsize_no;
	uint16_t keytype;
	unsigned char *passptr1;
	unsigned char *passptr2;
	uint32_t      sealinfosize;
	uint32_t      encdatasize;
	uint32_t      storedsize;
	unsigned char *encrypted;
	STACK_TPM_BUFFER( pil_ser )

	if (NULL == tpmdata) {
		return ERR_MEM_ERR;
	}

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	memset(dummyauth,0,sizeof dummyauth);
	/* check input arguments */
	if (data == NULL || blob == NULL) 
		return ERR_NULL_ARG;
	if (pil == NULL) 
		return ERR_NULL_ARG;
	if (keyhandle == 0x40000000) keytype = 0x0004;
	else                         keytype = 0x0001;
	if (keyauth  == NULL) passptr1 = dummyauth;
	else                  passptr1 = keyauth;
	if (dataauth == NULL) passptr2 = dummyauth;
	else                  passptr2 = dataauth;
	
	ret = TPM_WritePCRInfoLong(&pil_ser, pil);
	if ((ret & ERR_MASK))
		return ret;	
	pcrsize_no = htonl(ret);
	
	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,
	                      &sess,passptr1,keytype,keyhandle);
	if (ret != 0) 
		return ret;

	/* calculate encrypted authorization value */
	TPM_CreateEncAuth(&sess, passptr2, encauth, 0);

	/* generate odd nonce */
	TSS_gennonce(nonceodd);

	/* move Network byte order data to variables for hmac calculation */

	/*
	 * Encrypt the data we are sending using MGF1 encryption...
	 * Build the seed first
	 */
	encrypted = malloc(datalen);
	if (NULL == encrypted) {
		return ERR_MEM_ERR;
	}

	ret = Sealx_DataEncrypt(data, datalen,
	                        &sess,
	                        nonceodd,
	                        encrypted);

	if ((ret & ERR_MASK)) {
		free(encrypted);
		return ret;
	}


	/* calculate authorization HMAC value */
	if (pcrsize_no == 0) {
		/* no pcr info specified */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal_no,
		                   TPM_HASH_SIZE,encauth,
		                   TPM_U32_SIZE,&pcrsize_no,
		                   TPM_U32_SIZE,&datsize,
		                   datalen,encrypted,
		                   0,0);
	} else {
		/* pcr info specified */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal_no,
		                   TPM_HASH_SIZE,encauth,
		                   TPM_U32_SIZE,&pcrsize_no,
		                   pil_ser.used,pil_ser.buffer,
		                   TPM_U32_SIZE,&datsize,
		                   datalen,encrypted,
		                   0,0);
	}
	if (ret != 0) {
		TSS_SessionClose(&sess);
		goto exit;
	}

	/* build the request buffer */
	ret = TSS_buildbuff("00 C2 T l l % @ @ L % o %",tpmdata,
	                             ordinal_no,
	                               keyhndl_no,
	                                 TPM_HASH_SIZE,encauth,
	                                   pil_ser.used,pil_ser.buffer,
	                                     datalen,encrypted,
	                                       TSS_Session_GetHandle(&sess),
	                                         TPM_NONCE_SIZE,nonceodd,
	                                           c,
	                                             TPM_HASH_SIZE,pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		goto exit;
	}
	
	
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata,"Sealx");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		goto exit;
	}
	/* calculate the size of the returned Blob */
	ret = tpm_buffer_load32(tpmdata,TPM_DATA_OFFSET + TPM_U32_SIZE, &sealinfosize);
	if ((ret & ERR_MASK)) {
		goto exit;
	}
	ret = tpm_buffer_load32(tpmdata,TPM_DATA_OFFSET + TPM_U32_SIZE+TPM_U32_SIZE+sealinfosize, &encdatasize);
	if ((ret & ERR_MASK)) {
		goto exit;
	}
	storedsize   = TPM_U32_SIZE + TPM_U32_SIZE + sealinfosize + TPM_U32_SIZE + encdatasize;
	/* check the HMAC in the response */
	ret = TSS_checkhmac1(tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     storedsize,TPM_DATA_OFFSET,
	                     0,0);
	if (ret != 0) {
		goto exit;
	}
	/* copy the returned blob to caller */
	memcpy(blob,
	       &tpmdata->buffer[TPM_DATA_OFFSET],
	       storedsize);
	*bloblen = storedsize;

exit:
	TSS_FreeTPMBuffer(tpmdata);
	free(encrypted);
	return ret;
}



static uint32_t MGF1_decrypt(unsigned char *data, uint32_t datalen,
                             session *sess,
                             unsigned char *nonceodd,
                             unsigned char *output)
{
	unsigned char *x1;
	struct tpm_buffer *seed;
	uint32_t seedsize;
	uint32_t ret = 0;
	uint32_t i = 0;
	/*
	 * Decrypt the data we have received using MGF1 decryption...
	 * Build the seed first
	 */
	x1 = malloc(datalen);
	if (NULL == x1) {
		return ERR_MEM_ERR;
	}

	seed = TSS_AllocTPMBuffer(TPM_NONCE_SIZE+TPM_NONCE_SIZE+sizeof("XOR")-1+TPM_HASH_SIZE);
	if (NULL == seed) {
		free(x1);
		return ERR_MEM_ERR;
	}

	ret = TSS_buildbuff("% % % %", seed,
	                     TPM_NONCE_SIZE, TSS_Session_GetENonce(sess),
	                       TPM_NONCE_SIZE, nonceodd,
	                         sizeof("XOR")-1, "XOR",
	                           TPM_HASH_SIZE, TSS_Session_GetAuth(sess));
	if ((ret & ERR_MASK) != 0) {
		goto exit;
	}
	seedsize = ret;
	TSS_MGF1(x1,
		 datalen,
		 seed->buffer,
		 seedsize);

	for (i = 0; i < datalen; i++) {
		output[i] = x1[i] ^ data[i];
	}
	ret = 0;
//printf("MGF1 dec. success!\n");
exit:
	TSS_FreeTPMBuffer(seed);
	free(x1);
	return ret;
}

static uint32_t Sealx_DataDecrypt(unsigned char *data, uint32_t datalen,
                                  session *sess,
                                  unsigned char *nonceodd,
                                  unsigned char *output)
{
	uint32_t ret = 0;
	int use_xor = 0;
	
	TPM_DetermineSessionEncryption(sess, &use_xor);
	if (use_xor) {
	        ret = MGF1_decrypt(data, datalen,
	                           sess,
	                           nonceodd,
	                           output);
	} else {
		ret = AES_CTR_crypt(data, datalen, 
		                    sess,
		                    nonceodd,
		                    output);
	}
	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Unseal a data object that has previously been encrypted with sealx       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to seal the data                 */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           or NULL if no password is required                             */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           or NULL if no password is required                             */
/*           both authorization values must be 20 bytes long                */
/* blob      is a pointer to an area to containing the sealed blob          */
/* bloblen   is the length of the sealed blob                               */
/* rawdata   is a pointer to an area to receive the unsealed data (max 256?)*/
/* datalen   is a pointer to a int to receive the length of the data        */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Unsealx(uint32_t keyhandle,
                     unsigned char *keyauth,
                     unsigned char *dataauth,
                     unsigned char *blob, uint32_t bloblen,
                     unsigned char *rawdata, uint32_t *datalen)
{
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char nonceodd2[TPM_NONCE_SIZE];
	unsigned char dummyauth[TPM_NONCE_SIZE];
	unsigned char *passptr1;
	unsigned char *passptr2;
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_Unseal);
	uint32_t keyhndl = htonl(keyhandle);
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	session sess;
	session sess2;

	memset(dummyauth,0,sizeof dummyauth);
	/* check input arguments */
	if (rawdata == NULL || blob == NULL) return ERR_NULL_ARG;
	if (dataauth == NULL) passptr2 = dummyauth;
	else                  passptr2 = dataauth;
	if (keyauth == NULL) passptr1 = dummyauth;
	else                 passptr1 = keyauth;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	/* open TWO OIAP sessions, one for the Key and one for the Data */
	ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,
	                      &sess,
	                      passptr1, TPM_ET_KEYHANDLE, keyhandle);
	if (ret != 0) 
		return ret;

	ret = TSS_SessionOpen(SESSION_OIAP,
	                      &sess2,
	                      passptr2, 0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* generate odd nonce */

	TSS_gennonce(nonceodd);
	TSS_gennonce(nonceodd2);
	/* calculate KEY authorization HMAC value */
	ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_NONCE_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE,&ordinal,
	                   bloblen,blob,
	                   0,0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* calculate DATA authorization HMAC value */
	ret = TSS_authhmac(authdata2,TSS_Session_GetAuth(&sess2),TPM_NONCE_SIZE,TSS_Session_GetENonce(&sess2),nonceodd2,c,
	                   TPM_U32_SIZE,&ordinal,
	                   bloblen,blob,
	                   0,0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* build the request buffer */
	/* the first session MUST be there since it provides 
	 * the even and odd nonces for the MGF1 decryption
	 */
	ret = TSS_buildbuff("00 C3 T l l % L % o % L % o %",&tpmdata,
	                             ordinal,
	                               keyhndl,
	                                 bloblen,blob,
	                                   TSS_Session_GetHandle(&sess),
	                                     TPM_NONCE_SIZE,nonceodd,
	                                       c,
	                                         TPM_HASH_SIZE,authdata1,
	                                           TSS_Session_GetHandle(&sess2),
	                                             TPM_NONCE_SIZE,nonceodd2,
	                                               c,
	                                                 TPM_HASH_SIZE,authdata2);

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"Unseal(x) - AUTH2");
	TSS_SessionClose(&sess);
	TSS_SessionClose(&sess2);

	if (ret != 0) {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, datalen);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac2(&tpmdata,ordinal,nonceodd,
	                     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     nonceodd2,
	                     TSS_Session_GetAuth(&sess2),TPM_HASH_SIZE,
	                     TPM_U32_SIZE,TPM_DATA_OFFSET,
	                     *datalen,TPM_DATA_OFFSET+TPM_U32_SIZE,
	                     0,0);

	if (ret != 0) {
		return ret;
	}

	ret = Sealx_DataDecrypt(&tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
	                        *datalen,
	                        &sess,
	                        nonceodd,
	                        rawdata);
 
	return ret;
}
