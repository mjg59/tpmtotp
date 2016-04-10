/********************************************************************************/
/*										*/
/*			     	TPM Key Handling Routines			*/
/*			     Written by J. Kravitz 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*        $Id: keys.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <oiaposap.h>
#include <tpmfunc.h>
#include <tpmutil.h>
#include <tpmkeys.h>
#include <tpm_constants.h>
#include "tpm_error.h"
#include <hmac.h>
#include <newserialize.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>


/****************************************************************************/
/*                                                                          */
/* Creates an endorsement key pair                                          */
/*                                                                          */
/* uses the following standard parameters in its request:                   */
/*                                                                          */
/* algorithm: RSA                                                           */
/* encScheme: enc_SCHEME                                                    */
/* sigScheme: TPM_SS_SASSAPKCS1v15_SHA1                                     */
/* numprimes: 2                                                             */
/* keybitlen: 2048                                                          */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* pubkeybuff   A pointer to an area that will hold the public key          */
/* pubkeybuflen is the size of the pubkeybuff as given by the caller and    */
/*              on returns the number of bytes copied into that buffer      */
/****************************************************************************/
uint32_t TPM_CreateEndorsementKeyPair(unsigned char * pubkeybuff,
                                      uint32_t * pubkeybuflen) {
	unsigned char nonce[TPM_HASH_SIZE];
	STACK_TPM_BUFFER(tpmdata)
	keydata k;
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_CreateEndorsementKeyPair);
	int serkeylen;
	STACK_TPM_BUFFER(serkey)
	uint32_t size;

	memset(&k, 0x0, sizeof(k));
	k.pub.algorithmParms.algorithmID = TPM_ALG_RSA;
	/* Should be ignored, but a certain HW TPM requires the correct encScheme */
	k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
	k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
	k.pub.algorithmParms.u.rsaKeyParms.keyLength = 2048;
	k.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;
	k.pub.algorithmParms.u.rsaKeyParms.exponentSize = 0;
	
	TSS_gennonce(nonce);
	
	serkeylen = TPM_WriteKeyInfo(&serkey, &k);

	if (serkeylen < 0) {
		return serkeylen;
	}

	ret = TSS_buildbuff("00 c1 T l % %",&tpmdata,
	                             ordinal_no,
	                               TPM_HASH_SIZE, nonce,
	                                 serkeylen, serkey.buffer);

	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"CreateEndorsementKeyPair");
	
	if (0 != ret) {
		return ret;
	}
	
	size = TSS_PubKeySize(&tpmdata, TPM_DATA_OFFSET ,0);
	if ((size & ERR_MASK)) 
		return size;

	*pubkeybuflen = MIN(*pubkeybuflen, size);

	if (NULL != pubkeybuff) {
		memcpy(pubkeybuff, 
		       &tpmdata.buffer[TPM_DATA_OFFSET], 
		       *pubkeybuflen);
	}
	
	/*
	 * Verify the checksum...
	 */
	{
		SHA_CTX sha;
		unsigned char digest[TPM_DIGEST_SIZE];
		SHA1_Init(&sha);
		SHA1_Update(&sha,
		            &tpmdata.buffer[TPM_DATA_OFFSET],
		            size);
		SHA1_Update(&sha,
		            nonce,
		            TPM_HASH_SIZE);
		SHA1_Final(digest,&sha);
		if (0 != memcmp(digest,
		                &tpmdata.buffer[TPM_DATA_OFFSET+size],
		                TPM_DIGEST_SIZE)) {
			ret = ERR_CHECKSUM;
		}
	}
	
	return ret;
}



/****************************************************************************/
/*                                                                          */
/* Creates an revocable endorsement key pair                                */
/*                                                                          */
/* uses the following standard parameters in its request:                   */
/*                                                                          */
/* algorithm: RSA                                                           */
/* encScheme: enc_SCHEME                                                    */
/* sigScheme: TPM_SS_SASSAPKCS1v15_SHA1                                     */
/* numPrimes: 2                                                             */
/* keybitlen: 2048                                                          */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* genreset     a boolean that determines whether to generate ekreset       */
/* inputekreset A pointer to a hash that is used as ekreset if genreset is  */
/*              FALSE                                                       */
/* pubkeybuff   A pointer to an area that will hold the public key          */
/* pubkeybuflen is the size of the pubkeybuff as given by the caller and    */
/*              on returns the number of bytes copied into that buffer      */
/****************************************************************************/
uint32_t TPM_CreateRevocableEK(TPM_BOOL genreset,
                               unsigned char * inputekreset,
                               pubkeydata * pubkey) {
	unsigned char nonce[TPM_HASH_SIZE];
	STACK_TPM_BUFFER( tpmdata)
	keydata k;
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_CreateRevocableEK);
	int serkeylen;
	STACK_TPM_BUFFER(serkey)
	uint32_t size;

	memset(&k, 0x0, sizeof(k));
	k.pub.algorithmParms.algorithmID = TPM_ALG_RSA;
	k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
	k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
	k.pub.algorithmParms.u.rsaKeyParms.keyLength = 2048;
	k.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;
	k.pub.algorithmParms.u.rsaKeyParms.exponentSize = 0;
	
	TSS_gennonce(nonce);
	
	serkeylen = TPM_WriteKeyInfo(&serkey, &k);

	if ( (serkeylen & ERR_MASK) != 0 ) {
		return serkeylen;
	}

	if (FALSE == genreset) {
		ret = TSS_buildbuff("00 c1 T l % % o %",&tpmdata,
		                             ordinal_no,
		                               TPM_HASH_SIZE, nonce,
		                                 serkeylen, serkey.buffer,
		                                   genreset,
		                                     TPM_HASH_SIZE, inputekreset);
	} else {
		unsigned char empty[TPM_HASH_SIZE];
		memset(empty, 0x0, TPM_HASH_SIZE);
		ret = TSS_buildbuff("00 c1 T l % % o %",&tpmdata,
		                             ordinal_no,
		                               TPM_HASH_SIZE, nonce,
		                                 serkeylen, serkey.buffer,
		                                   genreset,
		                                     TPM_HASH_SIZE, empty);
	}

	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"CreateRevocableEK");

	if (0 != ret) {
		return ret;
	}

	size = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET, pubkey);
	/*
	 * Verify the checksum...
	 */
	{
		SHA_CTX sha;
		unsigned char digest[TPM_DIGEST_SIZE];
		SHA1_Init(&sha);
		SHA1_Update(&sha,
		            &tpmdata.buffer[TPM_DATA_OFFSET],
		            size);
		SHA1_Update(&sha,
		            nonce,
		            TPM_HASH_SIZE);
		SHA1_Final(digest,&sha);
		if (0 != memcmp(digest,
		                &tpmdata.buffer[TPM_DATA_OFFSET+size],
		                TPM_DIGEST_SIZE)) {
			ret = -1;
		}
	}

	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Clear the EK and reset the TPM to default state                          */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* inputekreset A pointer to a hash that is used as ekreset                 */
/*              It must match the parameter passed to CreateRevocableEK     */
/****************************************************************************/
uint32_t TPM_RevokeTrust(unsigned char *ekreset)
{
	STACK_TPM_BUFFER( tpmdata)
	uint32_t ordinal_no;
	uint32_t ret;
	
	/* check input arguments */
	if (NULL == ekreset) return ERR_NULL_ARG;


	/* move Network byte order data to variable for hmac calculation */
	ordinal_no = htonl(TPM_ORD_RevokeTrust);

	/* build the request buffer */
	ret = TSS_buildbuff("00 c1 T l %", &tpmdata,
	                             ordinal_no,
	                               TPM_NONCE_SIZE,ekreset);

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"RevokeTrust");
	
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Read the TPM Endorsement public key                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_ReadPubek(pubkeydata *k)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ret;
	uint32_t len;
	unsigned char antiReplay[TPM_NONCE_SIZE];

	/* check input argument */
	if (k == NULL) 
		return ERR_NULL_ARG;

	ret = TSS_gennonce(antiReplay);
	if (ret == 0) 
		return ERR_CRYPT_ERR;

	/* copy Read PubKey request template to buffer */
	ret = TSS_buildbuff("00 c1 T 00 00 00 7c %",&tpmdata,
                                                 TPM_HASH_SIZE, antiReplay);
	if ((ret & ERR_MASK) != 0) return ret;
	ret = TPM_Transmit(&tpmdata,"ReadPubek");
	if (ret) 
		return ret;
	len = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET ,k);
	
	/*
	 * Verify the checksum...
	 */
	{
		SHA_CTX sha;
		unsigned char digest[TPM_DIGEST_SIZE];
		SHA1_Init(&sha);
		SHA1_Update(&sha,
		            &tpmdata.buffer[TPM_DATA_OFFSET],
		            len);
		SHA1_Update(&sha,
		            antiReplay,
		            TPM_HASH_SIZE);
		SHA1_Final(digest,&sha);
		if (0 != memcmp(digest,
		                &tpmdata.buffer[TPM_DATA_OFFSET+len],
		                TPM_DIGEST_SIZE)) {
			ret = -1;
		}
	}
	
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Owner Read the TPM Endorsement Key                                       */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OwnerReadPubek(unsigned char *ownauth,pubkeydata *k)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   unsigned char nonceodd[TPM_NONCE_SIZE];
   unsigned char authdata[TPM_NONCE_SIZE];
   unsigned char c = 0;
   uint32_t ordinal = htonl(0x7D);
   uint32_t len;
   int size;
   session sess;

   /* generate odd nonce */
   TSS_gennonce(nonceodd);
   /* Open OIAP Session */
   ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
                         &sess,
                         ownauth, TPM_ET_OWNER, 0);
   if (ret != 0) return ret;

   /* calculate authorization HMAC value */
   ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
                      TPM_U32_SIZE,&ordinal,
                      0,0);
   if ((ret & ERR_MASK))
      {
      TSS_SessionClose(&sess);
      return ret;
      }
   /* build the request buffer */
   ret = TSS_buildbuff("00 c2 T l L % o %",&tpmdata,
                   ordinal,
                   TSS_Session_GetHandle(&sess),
                   TPM_NONCE_SIZE,nonceodd,
                   c,
                   TPM_HASH_SIZE,authdata);
   if ((ret & ERR_MASK) != 0)
      {
      TSS_SessionClose(&sess);
      return ret;
      }
   /* transmit the request buffer to the TPM device and read the reply */
   ret = TPM_Transmit(&tpmdata,"OwnerReadEkey");
   TSS_SessionClose(&sess);
   if (ret != 0)
      {
      return ret;
      }
   size = TSS_PubKeySize(&tpmdata, TPM_DATA_OFFSET, 0);
   ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
                        size,TPM_DATA_OFFSET,
                        0,0);
   if (ret != 0) return ret;
   len = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET, k);
   if ((len & ERR_MASK)) 
       return len;
   return 0;
   }

/****************************************************************************/
/*                                                                          */
/* Disable Reading of the Public Endorsement Key                            */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_DisablePubekRead(unsigned char *ownauth)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   unsigned char nonceodd[TPM_NONCE_SIZE];
   unsigned char authdata[TPM_NONCE_SIZE];
   unsigned char c = 0;
   uint32_t ordinal = htonl(TPM_ORD_DisablePubekRead);
   session sess;

   /* generate odd nonce */
   TSS_gennonce(nonceodd);
   /* Open OIAP Session */
   ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP|SESSION_OIAP,
                         &sess,
                         ownauth, TPM_ET_OWNER, 0);
   if (ret != 0) return ret;
   /* move Network byte order data to variables for hmac calculation */
   /* calculate authorization HMAC value */
   ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
                      TPM_U32_SIZE,&ordinal,
                      0,0);
   if ((ret & ERR_MASK))
      {
      TSS_SessionClose(&sess);
      return ret;
      }
   /* build the request buffer */
   ret = TSS_buildbuff("00 c2 T l L % o %",&tpmdata,
                   ordinal,
                   TSS_Session_GetHandle(&sess),
                   TPM_NONCE_SIZE,nonceodd,
                   c,
                   TPM_HASH_SIZE,authdata);
   if ((ret & ERR_MASK) != 0)
      {
      TSS_SessionClose(&sess);
      return ret;
      }
   /* transmit the request buffer to the TPM device and read the reply */
   ret = TPM_Transmit(&tpmdata,"DisablePubekRead");
   TSS_SessionClose(&sess);
   if (ret != 0)
      {
      return ret;
      }
   ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
                        0,0);
   if (ret != 0) return ret;
   return 0;
   }

/****************************************************************************/
/*                                                                          */
/* Return the public portion of the EK or SRK                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the parent key of the new key                 */
/*           which may only be PUBEK or 0x40000000 for the SRK              */
/* ownauth   The sha'ed owner password of the TPM                           */
/* pubkeybuf is a pointer to an area that will hold the public portion of   */
/*           the requested key                                              */
/* pubkeybuflen gives the size of the buffer pubkeybuf on input and will    */
/*              return the size of the public key part on output.           */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OwnerReadInternalPub(uint32_t keyhandle,
                                  unsigned char * ownerauth,
                                  pubkeydata *k)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no   = htonl(TPM_ORD_OwnerReadInternalPub);
	uint32_t keyhandle_no = htonl(keyhandle);
	uint32_t ret;
	uint32_t keylen;
	session sess;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) return ERR_CRYPT_ERR;
	
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      ownerauth, TPM_ET_OWNER, 0);
	if (ret != 0) return ret;

	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE, &ordinal_no,
	                   TPM_U32_SIZE, &keyhandle_no,
	                   0,0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}

	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l L % o %", &tpmdata,
	                             ordinal_no,
	                               keyhandle_no,
	                                 TSS_Session_GetHandle(&sess),
	                                   TPM_NONCE_SIZE,nonceodd,
	                                     c,
	                                       TPM_HASH_SIZE,authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	ret = TPM_Transmit(&tpmdata,"OwnerReadInternalPub");
	TSS_SessionClose(&sess);
	if (0 != ret) {
		return ret;
	}
	
	keylen = TSS_PubKeySize(&tpmdata, TPM_DATA_OFFSET, 0);
	if ((keylen & ERR_MASK)) {
		return keylen;
	}

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     keylen, TPM_DATA_OFFSET,
	                     0,0);

	if (0 != ret) {
		return ret;
	}
	
	keylen = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET, k);
	if ((keylen & ERR_MASK)) {
		ret = keylen;
	}

	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Create and Wrap a Key                                                    */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the parent key of the new key                 */
/*           0x40000000 for the SRK                                         */
/* parauth   is the authorization data (password) for the parent key        */
/*           if NULL, the default auth data of all zeros is assumed         */
/* newauth   is the authorization data (password) for the new key           */
/* migauth   is the authorization data (password) for migration of the new  */
/*           key, or NULL if the new key is not migratable                  */
/*           all authorization values must be 20 bytes long                 */
/* keyparms  is a pointer to a keydata structure with parms set for the new */
/*           key                                                            */
/* key       is a pointer to a keydata structure returned filled in         */
/*           with the public key data for the new key, or NULL if no        */
/*           keydata is to be returned                                      */
/* keyblob   is a pointer to an area which will receive a copy of the       */
/*           encrypted key blob.  If NULL no copy is returned               */
/* bloblen   is a pointer to an integer which will receive the length of    */
/*           the key blob, or NULL if no length is to be returned           */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_CreateWrapKey(uint32_t keyhandle,
                           unsigned char *parauth,
                           unsigned char *newauth,
                           unsigned char *migauth,
                           keydata *keyparms,
                           keydata *key,
                           unsigned char *keyblob,
                           unsigned int  *bloblen)
   {
	uint32_t ret;
	STACK_TPM_BUFFER( tpmdata)
	STACK_TPM_BUFFER(kparmbuf)
	session sess;
	unsigned char encauth1[TPM_HASH_SIZE];
	unsigned char encauth2[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char dummyauth[TPM_HASH_SIZE];
	unsigned char *cparauth;
	unsigned char *cnewauth;
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_CreateWrapKey);
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t keytype;
	int      kparmbufsize;
	STACK_TPM_BUFFER(response);

	memset(dummyauth,0,sizeof dummyauth);
	/* check input arguments */
	if (keyparms == NULL) return ERR_NULL_ARG;
	if (parauth == NULL) cparauth = dummyauth;
	else                 cparauth = parauth;
	if (newauth == NULL) cnewauth = dummyauth;
	else                 cnewauth = newauth;
	if (keyhandle == 0x40000000) keytype = 0x0004;
	else                         keytype = 0x0001;
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}
	
	if (keyparms->v.tag != TPM_TAG_KEY12) {
		/* get the TPM version and put into the keyparms structure */
		ret = TPM_GetCapability(TPM_CAP_VERSION,
		                        NULL,
		                        &response);
		if (ret != 0)
			return ret;
		memcpy(&(keyparms->v.ver), response.buffer, response.used);
	}

	/* generate odd nonce */
	TSS_gennonce(nonceodd);

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,cparauth,keytype,keyhandle);
	if (ret != 0) 
		return ret;

	TPM_CreateEncAuth(&sess, cnewauth, encauth1, NULL);
	/* calculate encrypted authorization value for migration of new key */
	if (migauth != NULL) {
		TPM_CreateEncAuth(&sess, migauth, encauth2, nonceodd);
	} else {
		memset(encauth2,0,TPM_HASH_SIZE);
	}
	/* move Network byte order data to variables for hmac calculation */
	/* convert keyparm structure to buffer */
	ret = TPM_WriteKey(&kparmbuf,keyparms);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	kparmbufsize = ret;
	/* calculate authorization HMAC value */
	ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE,&ordinal,
	                   TPM_HASH_SIZE,encauth1,
	                   TPM_HASH_SIZE,encauth2,
	                   kparmbufsize,kparmbuf.buffer,
	                   0,0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l % % % L % o %",&tpmdata,
	                             ordinal,
	                               keyhndl,
	                                 TPM_HASH_SIZE,encauth1,
	                                   TPM_HASH_SIZE,encauth2,
	                                     kparmbufsize,kparmbuf.buffer,
	                                       TSS_Session_GetHandle(&sess),
	                                         TPM_NONCE_SIZE,nonceodd,
	                                           c,
	                                             TPM_HASH_SIZE,pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"CreateWrapKey - AUTH1");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		return ret;
   	}
	kparmbufsize = TSS_KeySize(&tpmdata, TPM_DATA_OFFSET);
	ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     kparmbufsize,TPM_DATA_OFFSET,
	                     0,0);
	if (ret != 0) 
		return ret;

	/* convert the returned key to a structure */
	if (key != NULL) 
		TSS_KeyExtract(&tpmdata, TPM_DATA_OFFSET ,key);

	/* copy the key blob to caller */
	if (keyblob != NULL) {
		memcpy(keyblob,&tpmdata.buffer[TPM_DATA_OFFSET],kparmbufsize);
		if (bloblen != NULL) *bloblen = kparmbufsize;
	}
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Load a new Key into the TPM                                              */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of parent key for the new key                    */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the parent requires no auth        */
/* keyparms  is a pointer to a keydata structure with all data  for the new */
/*           key                                                            */
/* newhandle is a pointer to a 32bit word which will receive the handle     */
/*           of the new key                                                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
                keydata *keyparms,uint32_t *newhandle)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   STACK_TPM_BUFFER(kparmbuf)
   unsigned char nonceodd[TPM_NONCE_SIZE];
   unsigned char pubauth[TPM_HASH_SIZE];
   unsigned char c = 0;
   uint32_t ordinal = htonl(TPM_ORD_LoadKey);
   uint32_t keyhndl;
   int      kparmbufsize;

   ret = needKeysRoom(keyhandle, 0, 0, 0);
   if (ret != 0) {
      return ret;
   }

   /* check input arguments */
   if (keyparms == NULL || newhandle == NULL) return ERR_NULL_ARG;
   if (keyauth != NULL) /* parent requires authorization */
      {
      session sess;
      /* generate odd nonce */
      TSS_gennonce(nonceodd);
      /* Open OIAP Session */
      ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP|SESSION_DSAP,
                            &sess,
                            keyauth, TPM_ET_KEYHANDLE, keyhandle);
      if (ret != 0) return ret;
      /* move Network byte order data to variables for hmac calculation */
      keyhndl = htonl(keyhandle);

      /* convert keyparm structure to buffer */
      ret = TPM_WriteKey(&kparmbuf,keyparms);
      if ((ret & ERR_MASK) != 0)
         {
         TSS_SessionClose(&sess);
         return ret;
         }
      kparmbufsize = ret;
      /* calculate authorization HMAC value */
      ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
                         TPM_U32_SIZE,&ordinal,
                         kparmbufsize,kparmbuf.buffer,
                         0,0);
      if ((ret & ERR_MASK))
         {
         TSS_SessionClose(&sess);
         return ret;
         }
      /* build the request buffer */
      ret = TSS_buildbuff("00 c2 T l l % L % o %",&tpmdata,
                      ordinal,
                      keyhndl,
                      kparmbufsize,kparmbuf.buffer,
                      TSS_Session_GetHandle(&sess),
                      TPM_NONCE_SIZE,nonceodd,
                      c,
                      TPM_HASH_SIZE,pubauth);
      if ((ret & ERR_MASK) != 0)
         {
         TSS_SessionClose(&sess);
         return ret;
         }
      /* transmit the request buffer to the TPM device and read the reply */
      ret = TPM_Transmit(&tpmdata,"LoadKey - AUTH1");
      TSS_SessionClose(&sess);
      if (ret != 0)
         {
         return ret;
         }
      ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
                           TPM_U32_SIZE,TPM_DATA_OFFSET,
                           0,0);
      if (ret != 0) return ret;
      ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, newhandle);
      if ((ret & ERR_MASK)) {
          return ret;
      }
      }
   else /* parent requires NO authorization */
      {
      /* move Network byte order data to variables for hmac calculation */
      keyhndl = htonl(keyhandle);
      /* convert keyparm structure to buffer */
      ret = TPM_WriteKey(&kparmbuf,keyparms);
      if ((ret & ERR_MASK) != 0) return ret;
      kparmbufsize = ret;
      /* build the request buffer */
      ret = TSS_buildbuff("00 c1 T l l %",&tpmdata,
                      ordinal,
                      keyhndl,
                      kparmbufsize,kparmbuf.buffer);
      if ((ret & ERR_MASK) != 0) return ret;
      /* transmit the request buffer to the TPM device and read the reply */
      ret = TPM_Transmit(&tpmdata,"LoadKey");
      if (ret != 0) return ret;
      ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET,newhandle);
      if ((ret & ERR_MASK)) {
          return ret;
      }
      }
   return 0;
   }

/****************************************************************************/
/*                                                                          */
/* Load a new Key into the TPM                                              */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of parent key for the new key                    */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the parent requires no auth        */
/* keyparms  is a pointer to a keydata structure with all data  for the new */
/*           key                                                            */
/* newhandle is a pointer to a 32bit word which will receive the handle     */
/*           of the new key                                                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_LoadKey2(uint32_t keyhandle, unsigned char *keyauth,
                      keydata *keyparms, uint32_t *newhandle)
{
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	STACK_TPM_BUFFER(kparmbuf)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_LoadKey2);
	uint32_t keyhndl = htonl(keyhandle);
	int      kparmbufsize;

	/* check input arguments */
	if (keyparms == NULL || newhandle == NULL) 
		return ERR_NULL_ARG;
		
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	if (keyauth != NULL) /* parent requires authorization */ {
		session sess;
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Open OIAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP|SESSION_DSAP,
		                      &sess,
		                      keyauth, TPM_ET_KEYHANDLE, keyhandle);
		if (ret != 0) 
			return ret;
		/* move Network byte order data to variables for hmac calculation */

		/* convert keyparm structure to buffer */
		ret = TPM_WriteKey(&kparmbuf,keyparms);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		kparmbufsize = ret;
		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   kparmbufsize,kparmbuf.buffer,
		                   0,0);
		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l % L % o %",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 kparmbufsize,kparmbuf.buffer,
		                                   TSS_Session_GetHandle(&sess),
		                                     TPM_NONCE_SIZE,nonceodd,
		                                       c,
		                                         TPM_HASH_SIZE,pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"LoadKey2 - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     0,0);
		if (ret != 0) 
			return ret;
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET,newhandle);
		if ((ret & ERR_MASK)) {
			return ret;
		}
	} else /* parent requires NO authorization */ {
		/* convert keyparm structure to buffer */
		ret = TPM_WriteKey(&kparmbuf,keyparms);
		if ((ret & ERR_MASK) != 0) 
			return ret;
		kparmbufsize = ret;
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l %",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 kparmbufsize,kparmbuf.buffer);
		if ((ret & ERR_MASK) != 0) 
			return ret;
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"LoadKey2");
		if (ret != 0) 
			return ret;
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET,newhandle);
		if ((ret & ERR_MASK)) {
			return ret;
		}
	}
	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Get a Public Key from the TPM                                            */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key to be read                            */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/*           if null, it is assumed that the key requires no authorization  */
/* keyblob   is a pointer to an area which will receive a copy of the       */
/*           public key blob.                                               */
/* keyblen   is a pointer to an integer which will receive the length of    */
/*           the key blob                                                   */
/*                                                                          */
/****************************************************************************/
static uint32_t TPM_GetPubKey_Internal(uint32_t keyhandle,
                                       unsigned char *keyauth,
                                       pubkeydata *pk)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   unsigned char nonceodd[TPM_NONCE_SIZE];
   unsigned char pubauth[TPM_HASH_SIZE];
   unsigned char c = 0;
   uint32_t ordinal = htonl(0x21);
   uint32_t keyhndl = htonl(keyhandle);
   int      size;
   
   /* check input arguments */
   if (pk == NULL) return ERR_NULL_ARG;
   if (keyauth != NULL) /* key requires authorization */
      {
      session sess;
      /* generate odd nonce */
      TSS_gennonce(nonceodd);
      /* Open OIAP Session */
      ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP|SESSION_DSAP,
                            &sess,
                            keyauth, TPM_ET_KEYHANDLE, keyhandle);
      if (ret != 0) return ret;

      /* calculate authorization HMAC value */
      ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
                         TPM_U32_SIZE,&ordinal,
                         0,0);
      if (ret != 0)
         {
         TSS_SessionClose(&sess);
         return ret;
         }
      /* build the request buffer */
      ret = TSS_buildbuff("00 c2 T l l L % o %",&tpmdata,
                      ordinal,
                      keyhndl,
                      TSS_Session_GetHandle(&sess),
                      TPM_NONCE_SIZE,nonceodd,
                      c,
                      TPM_HASH_SIZE,pubauth);
      if ((ret & ERR_MASK) != 0)
         {
         TSS_SessionClose(&sess);
         return ret;
         }
      /* transmit the request buffer to the TPM device and read the reply */
      ret = TPM_Transmit(&tpmdata,"GetPubKey - AUTH1");
      TSS_SessionClose(&sess);
      if (ret != 0)
         {
         return ret;
         }
      ret = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET, pk);
      if ((ret & ERR_MASK)) 
          return ret;
      size = ret;
      ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
                           size,TPM_DATA_OFFSET,
                           0,0);
      if (ret != 0) return ret;
   } else /* key requires NO authorization */ {
      /* build the request buffer */
      ret = TSS_buildbuff("00 c1 T l l",&tpmdata,
                      ordinal,
                      keyhndl);
      if ((ret & ERR_MASK) != 0) return ret;
      /* transmit the request buffer to the TPM device and read the reply */
      ret = TPM_Transmit(&tpmdata,"GetPubKey - NO AUTH");
      if (ret != 0) return ret;
      ret = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET, pk);
      if ((ret & ERR_MASK))
          return ret;
      }
   return 0;
   }


uint32_t TPM_GetPubKey_UseRoom(uint32_t keyhandle,
                               unsigned char *keyauth,
                               pubkeydata *pk)
{
    uint32_t ret;
    uint32_t replaced_keyhandle;

    /* swap in keyhandle */
    ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle);
    if (ret != 0)
        return ret;

    ret = TPM_GetPubKey_Internal(keyhandle, keyauth, pk);

    needKeysRoom_Stacked_Undo(keyhandle, replaced_keyhandle);

    return ret;
}

uint32_t TPM_GetPubKey(uint32_t keyhandle,
                       unsigned char *keyauth,
                       pubkeydata *pk)
{
    uint32_t ret;

    ret = needKeysRoom(keyhandle, 0, 0, 0);
    if (ret != 0)
        return ret;

    return TPM_GetPubKey_Internal(keyhandle, keyauth, pk);
}

/****************************************************************************/
/*                                                                          */
/* Evict (delete) a  Key from the TPM                                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key to be evicted                         */
/*                                                                          */
/****************************************************************************/
static uint32_t TPM_EvictKey_Internal(uint32_t keyhandle, int allowTransport)
   {
   uint32_t ret;
   STACK_TPM_BUFFER( tpmdata)
   char *version = getenv("TPM_VERSION");

   if (version == NULL || !strcmp("11",version)) {
     ret = TSS_buildbuff("00 c1 T 00 00 00 22 L",&tpmdata, keyhandle);
     if ((ret & ERR_MASK) != 0) return ret;
     /* transmit the request buffer to the TPM device and read the reply */
     if (allowTransport)
         ret = TPM_Transmit(&tpmdata, "EvictKey");
     else
         ret = TPM_Transmit_NoTransport(&tpmdata, "EvictKey");
     if (ret == TPM_BAD_ORDINAL) {
       ret = TPM_FlushSpecific(keyhandle, TPM_RT_KEY);
     }
   } else {
       ret = TPM_FlushSpecific(keyhandle, TPM_RT_KEY);
   }
   return ret;
}

uint32_t TPM_EvictKey_UseRoom(uint32_t keyhandle)
{
        uint32_t ret;

        /*
         * To avoid recursion and major problems we assume for
         * this implementation here that the keyhandle is in
         * the TPM.
         *
         * uint32_t replaced_keyhandle;
         *
         * ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle);
         * if (ret != 0)
         *        return 0;
         */

        ret = TPM_EvictKey_Internal(keyhandle, 0);

        /*
         * needKeysRoom_Stacked_Undo(0, replaced_keyhandle);
         */

        return ret;
}


uint32_t TPM_EvictKey(uint32_t keyhandle)
{
        uint32_t ret;

        ret = needKeysRoom(keyhandle, 0, 0, 0);
        if (ret != 0)
                return 0;

        return TPM_EvictKey_Internal(keyhandle, 1);
}

/****************************************************************************/
/*                                                                          */
/* Extract a Pubkey Blob from a Key Blob                                    */
/*                                                                          */
/****************************************************************************/
void TSS_Key2Pub(unsigned char *keybuff, unsigned char *pkey, unsigned int *plen)
   {
   int srcoff1;
   int srcoff2;
   int srcoff3;
   int dstoff1;
   int dstoff2;
   int dstoff3;
   int len1;
   int len2;
   int len3;
   
   int pointer;
   int parmsize;
   int pcrisize;
   int pubksize;

   srcoff1 = TPM_U32_SIZE + TPM_U16_SIZE + TPM_U32_SIZE + 1;
   dstoff1 = 0;
   len1   = TPM_U32_SIZE + TPM_U16_SIZE + TPM_U16_SIZE + TPM_U32_SIZE;
   memcpy(pkey+dstoff1,keybuff+srcoff1,len1);
   dstoff2 = dstoff1 + len1;
   srcoff2 = srcoff1 + len1;
   pointer = srcoff1 + TPM_U32_SIZE + TPM_U16_SIZE + TPM_U16_SIZE;
   parmsize = LOAD32(keybuff,pointer);
   len2 = parmsize;
   memcpy(pkey+dstoff2,keybuff+srcoff2,len2);
   pointer = pointer + TPM_U32_SIZE + parmsize;
   pcrisize = LOAD32(keybuff,pointer);
   pointer = pointer + TPM_U32_SIZE + pcrisize;
   pubksize = LOAD32(keybuff,pointer);
   dstoff3 = dstoff2 + len2;
   srcoff3 = pointer;
   len3 = pubksize + TPM_U32_SIZE;
   memcpy(pkey+dstoff3,keybuff+srcoff3,len3);
   *plen = len1 + len2 + len3;
   }
   
/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Key Blob                                         */
/*                                                                          */
/****************************************************************************/
int TSS_KeySize(const struct tpm_buffer *tb, unsigned int offset)
{
	int      privkeylen;
	const unsigned char *keybuff = tb->buffer;
	unsigned int len;
	unsigned int offset_in = offset;

	offset += 0 + 4 + TPM_U16_SIZE + TPM_U32_SIZE + 1;
	len = TSS_PubKeySize(tb,offset,1);
	if ((len & ERR_MASK)) {
		return len;
	}
	offset += len;
	privkeylen = LOAD32(keybuff,offset);
	offset += TPM_U32_SIZE + privkeylen;
	return (offset - offset_in);
}
   
/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Public Key Blob                                  */
/*                                                                          */
/****************************************************************************/
int TSS_PubKeySize(const struct tpm_buffer *tb, unsigned int offset, int pcrpresent)
{
	uint32_t parmsize;
	uint32_t pcrisize;
	uint32_t keylength;
	const unsigned char *keybuff = tb->buffer;
	uint32_t offset_in = offset;
   
	offset += TPM_U32_SIZE + TPM_U16_SIZE + TPM_U16_SIZE;
	if (offset + 4 >= tb->used) {
		return ERR_STRUCTURE;
	}
	parmsize = LOAD32(keybuff,offset);
	offset += TPM_U32_SIZE;
	offset += parmsize;
	if (pcrpresent) {
		if (offset + 4 >= tb->used) {
			return ERR_STRUCTURE;
		}
		pcrisize  = LOAD32(keybuff,offset);
		offset += TPM_U32_SIZE;
		offset += pcrisize;
	}
	if (offset + 4 >= tb->used) {
		return ERR_STRUCTURE;
	}
	keylength = LOAD32(keybuff,offset);
	offset += TPM_U32_SIZE;
	offset += keylength;
	if (offset > tb->used) {
		return ERR_STRUCTURE;
	}
	return (offset - offset_in);
}

/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Asymmetric Key Blob                              */
/*                                                                          */
/****************************************************************************/
int TSS_AsymKeySize(const unsigned char * keybuff) 
{
	int offset = sizeof(TPM_ALGORITHM_ID) + sizeof(TPM_ENC_SCHEME);
	int size;
	size = LOAD16(keybuff, offset);
	size += sizeof(TPM_ALGORITHM_ID) + sizeof(TPM_ENC_SCHEME) + TPM_U16_SIZE;
	return size;
}

/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Symmetric Key Blob                              */
/*                                                                          */
/****************************************************************************/
int TSS_SymKeySize(const unsigned char * keybuff) {
	return TSS_AsymKeySize(keybuff);
}



/****************************************************************************/
/*                                                                          */
/* Convert a TPM public key to an OpenSSL RSA public key                    */
/*                                                                          */
/****************************************************************************/
RSA *TSS_convpubkey(pubkeydata *k)
   {
   RSA  *rsa;
   BIGNUM *mod;
   BIGNUM *exp;
   
   /* create the necessary structures */
   rsa = RSA_new();
   mod = BN_new();
   exp = BN_new();
   if (rsa == NULL || mod == NULL || exp == NULL) {
      if (rsa) {
         RSA_free(rsa);
      }
      if (mod) {
         BN_free(mod);
      }
      if (exp) {
         BN_free(exp);
      }
      return NULL;
   }
   /* convert the raw public key values to BIGNUMS */
   BN_bin2bn(k->pubKey.modulus,k->pubKey.keyLength,mod);
   if (0 == k->algorithmParms.u.rsaKeyParms.exponentSize) {
      unsigned char exponent[3] = {0x1,0x0,0x1};
      BN_bin2bn(exponent,3,exp);
   } else {
      BN_bin2bn(k->algorithmParms.u.rsaKeyParms.exponent,
                k->algorithmParms.u.rsaKeyParms.exponentSize,
                exp);
   }
   /* set up the RSA public key structure */
   rsa->n = mod;
   rsa->e = exp;
   return rsa;
   }


/****************************************************************************/
/*                                                                          */
/* Get the Fingerprint of a Key given a pubkeydata structure                */
/*                                                                          */
/****************************************************************************/
void TSS_pkeyprint(pubkeydata *key, unsigned char *fprint)
   {
   TSS_sha1(key->pubKey.modulus,key->pubKey.keyLength,fprint);
   }
   
/****************************************************************************/
/*                                                                          */
/* Get the Fingerprint of a Key given a key blob                            */
/*                                                                          */
/****************************************************************************/
void TSS_keyprint(unsigned char *keybuff, unsigned char *fprint)
   {
   keydata k;
   STACK_TPM_BUFFER(buffer);
   SET_TPM_BUFFER(&buffer, keybuff, sizeof(TPM_KEY_EMB));
   
   TSS_KeyExtract(&buffer, 0,&k);
   TSS_pkeyprint(&(k.pub),fprint);
   }
   
/****************************************************************************/
/*                                                                          */
/* Get the Fingerprint of a Key given a loaded key handle and authdata      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_lkeyprint(uint32_t keyhandle, unsigned char *keyauth, unsigned char *fprint)
   {
   uint32_t ret;
   pubkeydata k;

   ret = TPM_GetPubKey(keyhandle, keyauth, &k);
   if (ret != 0) return ret;
   TSS_pkeyprint(&k,fprint);
   return 0;
   }



/****************************************************************************/
/*                                                                          */
/* Certify a key                                                            */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* certhandle   is the handle of the key used to certify they               */
/* keyhandle    is the handle of the key to be certified                    */
/* antiReplay   points to a TPM_NONCE_SIZE (20) bytes large buffer          */
/*              containing an anti replay nonce                             */
/* certKeyAuth  is a pointer to a password (may be NULL)                    */
/* usageAuth    is a pointer to a password to inputs and key to be signed   */
/* certifyInfo  is a pointer to an area that will receive the certifyInfo   */
/*              blob upon return                                            */
/* certifyInfoLen  is a pointer to an integer that indicates the size of    */
/*                 the certifyInfo buffer on input and indicates the number */
/*                 of valid bytes on output                                 */
/* outData      is a pointer to a buffer that will receive the signed       */
/*              public key on return                                        */
/* outDataSize  is a pointer to an integer that holds the size of the       */
/*               outData buffer on input and the actual numbers of valid    */
/*              data used in that buffer on output.                         */
/****************************************************************************/
uint32_t TPM_CertifyKey(uint32_t certhandle,
                        uint32_t keyhandle,
                        unsigned char *certKeyAuth,
                        unsigned char *usageAuth,
                        struct tpm_buffer *certifyInfo_ser,
                        struct tpm_buffer *signature)
{
	uint32_t ret = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CertifyKey);
	unsigned char c = 0;
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata1[TPM_NONCE_SIZE];
	unsigned char antiReplay[TPM_HASH_SIZE];
	STACK_TPM_BUFFER(tpmdata)
	uint32_t certHandle_no = htonl(certhandle);
	uint32_t keyHandle_no = htonl(keyhandle);
	uint32_t ci_size;
	uint32_t len;
	session sess;

	if (NULL == usageAuth) {
		return ERR_NULL_ARG;
	}
	
	ret = needKeysRoom(certhandle, keyhandle, 0, 0);
	if (ret != 0) {
		return ret;
	}

	TSS_gennonce(antiReplay);
	TSS_gennonce(nonceodd);
	
	if (NULL != certKeyAuth) {
		session sess2;
		unsigned char authdata2[TPM_NONCE_SIZE];
		unsigned char nonceodd2[TPM_NONCE_SIZE];

		TSS_gennonce(nonceodd2);

		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP|SESSION_DSAP,
		                      &sess,
		                      certKeyAuth, TPM_ET_KEYHANDLE, certhandle);

		if (0 != ret) {
			return ret;
		}
		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess2,
		                      usageAuth,0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_NONCE_SIZE, antiReplay,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}
		ret = TSS_authhmac(authdata2,TSS_Session_GetAuth(&sess2),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess2),nonceodd2,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_NONCE_SIZE, antiReplay,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}
		ret = TSS_buildbuff("00 c3 T l l l % L % o % L % o %", &tpmdata,
		                             ordinal_no,
		                               certHandle_no,
		                                 keyHandle_no,
		                                   TPM_HASH_SIZE, antiReplay,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_NONCE_SIZE,nonceodd,
		                                         c,
		                                           TPM_HASH_SIZE, authdata1,
		                                             TSS_Session_GetHandle(&sess2),
		                                               TPM_NONCE_SIZE,nonceodd2,
		                                                 c,
		                                                   TPM_HASH_SIZE,authdata2);


		if (( ret & ERR_MASK ) !=  0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"CertifyKey - AUTH2");
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);

		if (0 != ret) {
			return ret;
		}

		ci_size = TPM_GetCertifyInfoSize(&tpmdata.buffer[TPM_DATA_OFFSET]);
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + ci_size, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TSS_checkhmac2(&tpmdata,ordinal_no,nonceodd,
		                     TSS_Session_GetAuth(&sess)   , TPM_HASH_SIZE,
		                     nonceodd2,
		                     TSS_Session_GetAuth(&sess2)  , TPM_HASH_SIZE,
		                     ci_size + TPM_U32_SIZE + len , TPM_DATA_OFFSET,
		                     0,0);

		if (0 != ret) {
			return ret;
		}

		if (NULL != certifyInfo_ser) {
			SET_TPM_BUFFER(certifyInfo_ser,
			               &tpmdata.buffer[TPM_DATA_OFFSET],
			               ci_size)
		}

		if (NULL != signature) {
			SET_TPM_BUFFER(signature,
			               &tpmdata.buffer[TPM_DATA_OFFSET + ci_size + TPM_U32_SIZE],
			               len);
		}

	} else {
		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess,
		                      usageAuth, 0, 0);
		if (0 != ret) {
			return ret;
		}

		ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_NONCE_SIZE, antiReplay,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TSS_buildbuff("00 c2 T l l l % L % o %", &tpmdata,
		                             ordinal_no,
		                               certHandle_no,
		                                 keyHandle_no,
		                                   TPM_HASH_SIZE, antiReplay,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_NONCE_SIZE,nonceodd,
		                                         c,
		                                           TPM_HASH_SIZE, authdata1);


		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"CertifyKey - AUTH1");
		TSS_SessionClose(&sess);

		if (0 != ret) {
			return ret;
		}

		ci_size = TPM_GetCertifyInfoSize(&tpmdata.buffer[TPM_DATA_OFFSET]);
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + ci_size, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     ci_size + TPM_U32_SIZE + len , TPM_DATA_OFFSET,
		                     0,0);

		if (0 != ret) {
			return ret;
		}

		if (NULL != certifyInfo_ser) {
			SET_TPM_BUFFER(certifyInfo_ser,
			               &tpmdata.buffer[TPM_DATA_OFFSET],
			               ci_size)
		}

		if (NULL != signature) {
			SET_TPM_BUFFER(signature,
			               &tpmdata.buffer[TPM_DATA_OFFSET + ci_size + TPM_U32_SIZE],
			               len);
		}
	}
	return ret;
}



/****************************************************************************/
/*                                                                          */
/* Certify a key                                                            */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* certhandle   is the handle of the key used to certify they               */
/* keyhandle    is the handle of the key to be certified                    */
/* migrationPubDigest is a pointer to a digest                              */
/* antiReplay   points to a TPM_NONCE_SIZE (20) bytes large buffer          */
/*              containing an anti replay nonce                             */
/* certKeyAuth  is a pointer to a password (may be NULL)                    */
/* usageAuth    is a pointer to a password to inputs and key to be signed   */
/* certifyInfo  is a pointer to an area that will receive the certifyInfo   */
/*              blob upon return                                            */
/* certifyInfoLen  is a pointer to an integer that indicates the size of    */
/*                 the certifyInfo buffer on input and indicates the number */
/*                 of valid bytes on output                                 */
/* outData      is a pointer to a buffer that will receive the signed       */
/*              public key on return                                        */
/* outDataSize  is a pointer to an integer that holds the size of the       */
/*               outData buffer on input and the actual numbers of valid    */
/*              data used in that buffer on output.                         */
/****************************************************************************/
uint32_t TPM_CertifyKey2(uint32_t certhandle,
                         uint32_t keyhandle,
                         unsigned char * migrationPubDigest,
                         unsigned char * certKeyAuth,
                         unsigned char * usageAuth,
                         struct tpm_buffer *certifyInfo_ser,
                         struct tpm_buffer *signature)
{
	uint32_t ret = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CertifyKey2);
	unsigned char c = 0;
	unsigned char authdata1[TPM_NONCE_SIZE];
	unsigned char antiReplay[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	STACK_TPM_BUFFER( tpmdata )
	uint32_t certHandle_no = htonl(certhandle);
	uint32_t keyHandle_no = htonl(keyhandle);
	uint32_t ci_size;
	uint32_t len;
	session sess;

	if (NULL == certKeyAuth ||
	    NULL == migrationPubDigest) {
		return ERR_NULL_ARG;
	}

	ret = needKeysRoom(certhandle, keyhandle, 0, 0);
	if (ret != 0) {
		return ret;
	}

	TSS_gennonce(antiReplay);
	TSS_gennonce(nonceodd);
	
	if (NULL != usageAuth) {
		unsigned char authdata2[TPM_NONCE_SIZE];
		unsigned char nonceodd2[TPM_NONCE_SIZE];
		session sess2;

		TSS_gennonce(nonceodd2);
		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess,
		                      usageAuth,0,0);
		if (0 != ret) {
			return ret;
		}
		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess2,
		                      certKeyAuth, 0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_HASH_SIZE, migrationPubDigest,
		                   TPM_NONCE_SIZE, antiReplay,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}
		ret = TSS_authhmac(authdata2,TSS_Session_GetAuth(&sess2),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess2),nonceodd2,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_HASH_SIZE, migrationPubDigest,
		                   TPM_NONCE_SIZE, antiReplay,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}
		ret = TSS_buildbuff("00 c3 T l l l % % L % o % L % o %", &tpmdata,
		                             ordinal_no,
		                               keyHandle_no,
		                                 certHandle_no,
		                                   TPM_DIGEST_SIZE, migrationPubDigest,
		                                     TPM_HASH_SIZE, antiReplay,
		                                       TSS_Session_GetHandle(&sess),
		                                         TPM_NONCE_SIZE,nonceodd,
		                                           c,
		                                             TPM_HASH_SIZE, authdata1,
		                                               TSS_Session_GetHandle(&sess2),
		                                                 TPM_NONCE_SIZE,nonceodd2,
		                                                   c,
		                                                     TPM_HASH_SIZE,authdata2);


		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"CertifyKey2 - AUTH2");
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);

		if (0 != ret) {
			return ret;
		}

		ci_size = TPM_GetCertifyInfoSize(&tpmdata.buffer[TPM_DATA_OFFSET]);
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + ci_size, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TSS_checkhmac2(&tpmdata,ordinal_no,nonceodd,
		                     TSS_Session_GetAuth(&sess)  , TPM_HASH_SIZE,
		                     nonceodd2,
		                     TSS_Session_GetAuth(&sess2) , TPM_HASH_SIZE,
		                     ci_size + TPM_U32_SIZE + len, TPM_DATA_OFFSET,
		                     0,0);

		if (0 != ret) {
			return ret;
		}

		if (NULL != certifyInfo_ser) {
			SET_TPM_BUFFER(certifyInfo_ser,
			               &tpmdata.buffer[TPM_DATA_OFFSET],
			               ci_size)
		}

		if (NULL != signature) {
			SET_TPM_BUFFER(signature,
			               &tpmdata.buffer[TPM_DATA_OFFSET + ci_size + TPM_U32_SIZE],
			               len);
		}
	} else {
		TSS_gennonce(nonceodd);
		ret = TSS_SessionOpen(SESSION_OIAP,
		                      &sess,
		                      certKeyAuth, 0,0);
		if (0 != ret) {
			return ret;
		}

		ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_HASH_SIZE, migrationPubDigest,
		                   TPM_NONCE_SIZE, antiReplay,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TSS_buildbuff("00 c2 T l l l % % l % o %", &tpmdata,
		                             ordinal_no,
 		                               keyHandle_no,
		                                 certHandle_no,
		                                   TPM_DIGEST_SIZE, migrationPubDigest,
		                                     TPM_HASH_SIZE, antiReplay,
		                                       TSS_Session_GetAuth(&sess),
		                                         TPM_NONCE_SIZE,nonceodd,
		                                           c,
		                                             TPM_HASH_SIZE, authdata1);


		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"CertifyKey2 - AUTH1");
		TSS_SessionClose(&sess);

		if (0 != ret) {
			return ret;
		}

		ci_size = TPM_GetCertifyInfoSize(&tpmdata.buffer[TPM_DATA_OFFSET]);
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + ci_size, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     ci_size + TPM_U32_SIZE + len , TPM_DATA_OFFSET,
		                     0,0);

		if (0 != ret) {
			return ret;
		}

		if (NULL != certifyInfo_ser) {
			SET_TPM_BUFFER(certifyInfo_ser,
			               &tpmdata.buffer[TPM_DATA_OFFSET],
			               ci_size)
		}

		if (NULL != signature) {
			SET_TPM_BUFFER(signature,
			               &tpmdata.buffer[TPM_DATA_OFFSET + ci_size + TPM_U32_SIZE],
			               len);
		}
	}
	return ret;
}

uint32_t TPM_GetPubKeyDigest(uint32_t keyhandle, unsigned char *keyPassHash,
                             unsigned char *digest)
{
	uint32_t ret;
	keydata k;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	ret = TPM_GetPubKey(keyhandle, keyPassHash,
	                    &k.pub);

	if (0 != ret) {
		return ret;
	}

	ret = TPM_HashPubKey(&k, digest);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	return 0;
}
