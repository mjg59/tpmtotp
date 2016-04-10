/********************************************************************************/
/*										*/
/*			     	TPM Key Migration Routines			*/
/*			     Written by J. Kravitz				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: migrate.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <oiaposap.h>
#include <tpmfunc.h>
#include <hmac.h>

/****************************************************************************/
/*                                                                          */
/* Authorize a Migration Key                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is a pointer to the Owner password (20 bytes)                  */
/* migtype   is an integer containing 1 for normal migration and 2 for      */
/*           rewrap migration                                               */
/* keyblob   is a pointer to an area containing the migration public         */
/*           encrypted key blob                                             */
/* migblob   is a pointer to an area which will receive the migration       */
/*           key authorization blob                                         */
/*                                                                          */
/****************************************************************************/
uint32_t
TPM_AuthorizeMigrationKey(unsigned char *ownpass,
			  int migtype,
			  struct tpm_buffer *keyblob,
			  struct tpm_buffer *migblob)
{
	uint32_t ret;

	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_AuthorizeMigrationKey);
	uint16_t migscheme = htons(migtype);
	uint32_t size;
	session sess;

	/* check input arguments */
	if (keyblob == NULL || migblob == NULL || ownpass == NULL)
		return ERR_NULL_ARG;

	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP | SESSION_OIAP,
			      &sess, ownpass, TPM_ET_OWNER, 0);

	if (ret != 0)
		return ret;

	/* calculate authorization HMAC value */
	ret = TSS_authhmac(pubauth, TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c,
			   TPM_U32_SIZE, &ordinal, 
			   TPM_U16_SIZE, &migscheme,
			   keyblob->used, keyblob->buffer, 
			   0, 0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l s % L % o %", &tpmdata,
			             ordinal,
			               migscheme,
			                 keyblob->used, keyblob->buffer,
			                   TSS_Session_GetHandle(&sess),
			                     TPM_NONCE_SIZE, nonceodd,
			                       c, 
			                         TPM_HASH_SIZE, pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "AuthorizeMigrationKey - AUTH1");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		return ret;
	}

	size = TSS_PubKeySize(&tpmdata, TPM_DATA_OFFSET, 0);
	if ((size & ERR_MASK)) {
		return size;
	}
	size += TPM_U16_SIZE + TPM_HASH_SIZE;	/* size of MigrationKeyAuth blob */
	ret = TSS_checkhmac1(&tpmdata, ordinal, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, size,
			     TPM_DATA_OFFSET, 0, 0);
	if (ret != 0)
		return ret;
	SET_TPM_BUFFER(migblob, &tpmdata.buffer[TPM_DATA_OFFSET], size);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Create Migration Blob                                                    */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the parent key of the key to                  */
/*           be migrated.                                                   */
/* keyauth   is the authorization data (password) for the parent key        */
/*           if null, it is assumed that the parent requires no auth        */
/* migauth   is the authorization data (password) for migration of          */
/*           the key being migrated                                         */
/*           all authorization values must be 20 bytes long                 */
/* migtype   is an integer containing 1 for normal migration and 2 for      */
/*           rewrap migration                                               */
/* migblob   is a pointer to an area to containing the migration key        */
/*           authorization blob.                                            */
/* migblen   is an integer containing the length of the migration key       */
/*           authorization blob                                             */
/* keyblob   is a pointer to an area which contains the                     */
/*           encrypted key blob of the key being migrated                   */
/* keyblen   is an integer containing the length of the encrypted key       */
/*           blob for the key being migrated                                */
/* rndblob   is a pointer to an area which will receive the random          */
/*           string for XOR decryption of the migration blob                */
/* rndblen   is a pointer to an integer which will receive the length       */
/*           of the random XOR string                                       */
/* outblob   is a pointer to an area which will receive the migrated        */
/*           key                                                            */
/* outblen   is a pointer to an integer which will receive the length       */
/*           of the migrated key                                            */
/*                                                                          */
/****************************************************************************/
uint32_t
TPM_CreateMigrationBlob(unsigned int keyhandle,
			unsigned char *keyauth,
			unsigned char *migauth,
			int migtype,
			unsigned char *migblob,
			uint32_t migblen,
			unsigned char *keyblob,
			uint32_t keyblen,
			unsigned char *rndblob,
			uint32_t *rndblen,
			unsigned char *outblob, uint32_t *outblen)
{
	uint32_t ret;

	ALLOC_TPM_BUFFER(tpmdata, 0)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal = htonl(TPM_ORD_CreateMigrationBlob);
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t migscheme = htons(migtype);
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	uint32_t size1;
	uint32_t size2;
	uint32_t keyblen_no = ntohl(keyblen);
	session sess;

	/* check input arguments */
	if (migauth == NULL || migblob == NULL || keyblob == NULL)
		return ERR_NULL_ARG;
	if (rndblob == NULL || rndblen == NULL || outblob == NULL ||
	    outblen == NULL)
		return ERR_NULL_ARG;
	if (migtype != 1 && migtype != 2)
		return ERR_BAD_ARG;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	/* generate odd nonce */
	TSS_gennonce(nonceodd);

	if (keyauth != NULL) {	/* parent key password is required */
		session sess2;
		unsigned char nonceodd2[TPM_NONCE_SIZE];
		TSS_gennonce(nonceodd2);

		/* open TWO OIAP sessions, one for the Parent Key Auth and one for the Migrating Key */
		ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP | SESSION_DSAP,
				      &sess,
				      keyauth, TPM_ET_KEYHANDLE, keyhandle);
		if (ret != 0) {
			goto exit;
		}
		ret = TSS_SessionOpen(SESSION_OIAP, &sess2, migauth, 0, 0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			goto exit;
		}
		/* calculate Parent KEY authorization HMAC value */
		ret = TSS_authhmac(authdata1, TSS_Session_GetAuth(&sess),
				   TPM_HASH_SIZE, TSS_Session_GetENonce(&sess),
				   nonceodd, c, 
				   TPM_U32_SIZE, &ordinal,
				   TPM_U16_SIZE, &migscheme, 
				   migblen, migblob,
				   TPM_U32_SIZE, &keyblen_no, 
				   keyblen, keyblob,
				   0, 0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			goto exit;
		}
		/* calculate Migration authorization HMAC value */
		ret = TSS_authhmac(authdata2, TSS_Session_GetAuth(&sess2),
				   TPM_HASH_SIZE,
				   TSS_Session_GetENonce(&sess2), nonceodd2, c,
				   TPM_U32_SIZE, &ordinal, 
				   TPM_U16_SIZE, &migscheme, 
				   migblen, migblob, 
				   TPM_U32_SIZE, &keyblen_no, 
				   keyblen, keyblob, 
				   0, 0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			goto exit;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c3 T l l s % @ L % o % L % o %",
				    tpmdata, ordinal, keyhndl, migscheme,
				    migblen, migblob, keyblen, keyblob,
				    TSS_Session_GetHandle(&sess),
				    TPM_NONCE_SIZE, nonceodd, c, TPM_HASH_SIZE,
				    authdata1, TSS_Session_GetHandle(&sess2),
				    TPM_NONCE_SIZE, nonceodd2, c, 
				    TPM_HASH_SIZE, authdata2);

		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			TSS_SessionClose(&sess2);
			goto exit;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "CreateMigrationBlob - AUTH2");
		TSS_SessionClose(&sess);
		TSS_SessionClose(&sess2);
		if (ret != 0) {
			goto exit;
		}
		/* validate HMAC in response */
		ret = tpm_buffer_load32(tpmdata, TPM_DATA_OFFSET, &size1);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		ret = tpm_buffer_load32(tpmdata,
			       TPM_DATA_OFFSET + TPM_U32_SIZE + size1, &size2);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		if (size1 != 0) {
			ret = TSS_checkhmac2(tpmdata, ordinal, nonceodd,
					     TSS_Session_GetAuth(&sess),
					     TPM_HASH_SIZE,
					     nonceodd2,
					     TSS_Session_GetAuth(&sess2),
					     TPM_HASH_SIZE, TPM_U32_SIZE,
					     TPM_DATA_OFFSET, size1,
					     TPM_DATA_OFFSET + TPM_U32_SIZE,
					     TPM_U32_SIZE,
					     TPM_DATA_OFFSET + TPM_U32_SIZE +
					     size1, size2,
					     TPM_DATA_OFFSET + TPM_U32_SIZE +
					     size1 + TPM_U32_SIZE, 0, 0);
		} else {
			ret = TSS_checkhmac2(tpmdata, ordinal, nonceodd,
					     TSS_Session_GetAuth(&sess),
					     TPM_HASH_SIZE,
					     nonceodd2,
					     TSS_Session_GetAuth(&sess2),
					     TPM_HASH_SIZE, TPM_U32_SIZE,
					     TPM_DATA_OFFSET, TPM_U32_SIZE,
					     TPM_DATA_OFFSET + TPM_U32_SIZE,
					     size2,
					     TPM_DATA_OFFSET + TPM_U32_SIZE +
					     TPM_U32_SIZE, 0, 0);
		}
		if (ret != 0)
			goto exit;
	} else {		/* no parent key password required */

		/* open OIAP session for the Migrating Key */
		ret = TSS_SessionOpen(SESSION_OIAP, &sess, migauth, 0, 0);
		if (ret != 0) {
			goto exit;
		}
		/* calculate Migration authorization HMAC value */
		ret = TSS_authhmac(authdata1, TSS_Session_GetAuth(&sess),
				   TPM_HASH_SIZE, TSS_Session_GetENonce(&sess),
				   nonceodd, c, TPM_U32_SIZE, &ordinal,
				   TPM_U16_SIZE, &migscheme, migblen, migblob,
				   TPM_U32_SIZE, &keyblen_no, keyblen, keyblob,
				   0, 0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			goto exit;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l s % @ L % o %", tpmdata,
				    ordinal,
				    keyhndl,
				    migscheme,
				    migblen, migblob,
				    keyblen, keyblob,
				    TSS_Session_GetHandle(&sess),
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, authdata1);

		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			goto exit;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "CreateMigrationBlob - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			goto exit;
		}
		/* check HMAC in response */
		ret = tpm_buffer_load32(tpmdata, TPM_DATA_OFFSET, &size1);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		ret = tpm_buffer_load32(tpmdata,
			       TPM_DATA_OFFSET + TPM_U32_SIZE + size1, &size2);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		if (size1 != 0) {
			ret = TSS_checkhmac1(tpmdata, ordinal, nonceodd,
					     TSS_Session_GetAuth(&sess),
					     TPM_HASH_SIZE, TPM_U32_SIZE,
					     TPM_DATA_OFFSET, size1,
					     TPM_DATA_OFFSET + TPM_U32_SIZE,
					     TPM_U32_SIZE,
					     TPM_DATA_OFFSET + TPM_U32_SIZE +
					     size1, size2,
					     TPM_DATA_OFFSET + TPM_U32_SIZE +
					     size1 + TPM_U32_SIZE, 0, 0);
		} else {
			ret = TSS_checkhmac1(tpmdata, ordinal, nonceodd,
					     TSS_Session_GetAuth(&sess),
					     TPM_HASH_SIZE, TPM_U32_SIZE,
					     TPM_DATA_OFFSET, TPM_U32_SIZE,
					     TPM_DATA_OFFSET + TPM_U32_SIZE,
					     size2,
					     TPM_DATA_OFFSET + TPM_U32_SIZE +
					     TPM_U32_SIZE, 0, 0);
		}
		if (ret != 0)
			goto exit;
	}
	memcpy(rndblob,
	       &tpmdata->buffer[TPM_DATA_OFFSET + TPM_U32_SIZE], size1);
	memcpy(outblob,
	       &tpmdata->buffer[TPM_DATA_OFFSET + TPM_U32_SIZE + size1 +
				TPM_U32_SIZE], size2);
	*rndblen = size1;
	*outblen = size2;
      exit:
	FREE_TPM_BUFFER(tpmdata);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Convert a Migration Blob                                                 */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the new parent key of the key                 */
/*           being migrated                                                 */
/* keyauth   is the authorization data (password) for the parent key        */
/* rndblob   is a pointer to an area containing the random XOR data         */
/* rndblen   is an integer containing the length of the random XOR data     */
/* keyblob   is a pointer to an area containing the migration public        */
/*           encrypted key blob                                             */
/* keyblen   is an integer containing the length of the migration           */
/*           public key blob                                                */
/* encblob   is a pointer to an area which will receive the migrated        */
/*           key re-encrypted private key blob                              */
/* endblen   is a pointer to an integer which will receive size of          */
/*           the migrated key re-encrypted private key blob                 */
/*                                                                          */
/****************************************************************************/
uint32_t
TPM_ConvertMigrationBlob(unsigned int keyhandle,
			 unsigned char *keyauth,
			 unsigned char *rndblob,
			 uint32_t rndblen,
			 unsigned char *keyblob,
			 uint32_t keyblen,
			 unsigned char *encblob, uint32_t *encblen)
{
	uint32_t ret;

	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_ConvertMigrationBlob);
	uint32_t keyhndl;
	uint32_t rndsize;
	uint32_t datsize;
	uint32_t size;

	/* check input arguments */
	if (rndblob == NULL ||
	    keyblob == NULL || encblob == NULL || encblen == NULL)
		return ERR_NULL_ARG;

	keyhndl = htonl(keyhandle);
	rndsize = htonl(rndblen);
	datsize = htonl(keyblen);
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	if (NULL != keyauth) {
		session sess;

		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Open OIAP Session */
		ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP | SESSION_OIAP,
				      &sess,
				      keyauth, TPM_ET_KEYHANDLE, keyhandle);
		if (ret != 0)
			return ret;
		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth, TSS_Session_GetAuth(&sess),
				   TPM_HASH_SIZE, TSS_Session_GetENonce(&sess),
				   nonceodd, c, TPM_U32_SIZE, &ordinal_no,
				   TPM_U32_SIZE, &datsize, keyblen, keyblob,
				   TPM_U32_SIZE, &rndsize, rndblen, rndblob, 0,
				   0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l @ @ L % o %", &tpmdata,
				    ordinal_no,
				    keyhndl,
				    keyblen, keyblob,
				    rndblen, rndblob,
				    TSS_Session_GetHandle(&sess),
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata, "ConvertMigrationBlob - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &size);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
				     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
				     TPM_U32_SIZE, TPM_DATA_OFFSET, size,
				     TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		if (ret != 0)
			return ret;
		memcpy(encblob,
		       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE], size);
		*encblen = size;
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l @ @", &tpmdata,
				    ordinal_no,
				    keyhndl,
				    keyblen, keyblob, rndblen, rndblob);

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata, "ConvertMigrationBlob - NOAUTH");
		if (ret != 0) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &size);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		if (ret != 0)
			return ret;
		memcpy(encblob,
		       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE], size);
		*encblen = size;
	}
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Migrate a key by re-encrypting its private key                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle    is the handle to the key that can decrypt the private key   */
/* keyUsageAuth is the hashed password for using the key, NULL if no the    */
/*              key does not need a password                                */
/* pubKeyBlob   is the blob of the public key where the 'key to be migrated'*/
/*              is supposed to be re-encrypted with                         */
/* inData       is the encrypted private key part of the key pair, currently*/
/*              encrypted with the public key of the key pointed to by      */
/*              keyhandle                                                   */
/* inDataSize   is the size of the inData blob                              */
/* outData      points to an area sufficiently large to hold the reencrypted*/
/*              private key; (should have the size inDataSize)              */
/* outDataSize  passes the size of outData block on input and returns the  */
/*              number of valid bytes on output                             */
/****************************************************************************/
uint32_t
TPM_MigrateKey(uint32_t keyhandle,
	       unsigned char *keyUsageAuth,
	       unsigned char *pubKeyBlob, uint32_t pubKeySize,
	       unsigned char *inData, uint32_t inDataSize,
	       unsigned char *outData, uint32_t * outDataSize)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = ntohl(TPM_ORD_MigrateKey);
	uint32_t ret;
	uint32_t keyhandle_no = htonl(keyhandle);
	uint32_t inDataSize_no = htonl(inDataSize);
	uint32_t len;

	/* check input arguments */
	if (NULL == pubKeyBlob || NULL == inData || NULL == outData) {
		return ERR_NULL_ARG;
	}
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	if (NULL != keyUsageAuth) {
		/* generate odd nonce */
		session sess;

		ret = TSS_gennonce(nonceodd);
		if (0 == ret)
			return ERR_CRYPT_ERR;

		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP | SESSION_OIAP,
				      &sess,
				      keyUsageAuth, TPM_ET_KEYHANDLE,
				      keyhandle);
		if (ret != 0)
			return ret;
		/* calculate encrypted authorization value */

		ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess),
				   TPM_HASH_SIZE, TSS_Session_GetENonce(&sess),
				   nonceodd, c, TPM_U32_SIZE, &ordinal_no,
				   pubKeySize, pubKeyBlob, TPM_U32_SIZE,
				   &inDataSize_no, inDataSize, inData, 0, 0);

		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l % @ L % o %", &tpmdata,
				    ordinal_no,
				    keyhandle_no,
				    pubKeySize, pubKeyBlob,
				    inDataSize, inData,
				    TSS_Session_GetHandle(&sess),
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, authdata);
		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata, "MigrateKey - AUTH1");
		TSS_SessionClose(&sess);

		if (ret != 0) {
			return ret;
		}

		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* check the HMAC in the response */

		ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
				     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
				     TPM_U32_SIZE + len, TPM_DATA_OFFSET, 0,
				     0);

		if (outData != NULL) {
			*outDataSize = MIN(*outDataSize, len);
			memcpy(outData,
			       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
			       *outDataSize);
		}
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l % @", &tpmdata,
				    ordinal_no,
				    keyhandle_no,
				    pubKeySize, pubKeyBlob,
				    inDataSize, inData);

		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata, "MigrateKey - AUTH1");

		if (ret != 0) {
			return ret;
		}

		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		if (outData != NULL) {
			*outDataSize = MIN(*outDataSize, len);
			memcpy(outData,
			       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
			       *outDataSize);
		}

	}

	return ret;
}

/****************************************************************************/
/*                                                                          */
/*                                                                          */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */

uint32_t
TPM_CMK_SetRestrictions(uint32_t restriction, unsigned char *ownerAuth)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CMK_SetRestrictions);
	uint32_t ret;
	uint32_t restriction_no = htonl(restriction);
	session sess;

	/* check input arguments */
	if (NULL == ownerAuth)
		return ERR_NULL_ARG;

	/* generate odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (0 == ret)
		return ERR_CRYPT_ERR;

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
			      &sess, ownerAuth, TPM_ET_OWNER, 0);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value */

	ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c,
			   TPM_U32_SIZE, &ordinal_no, TPM_U32_SIZE,
			   &restriction_no, 0, 0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l L % o %", &tpmdata,
			    ordinal_no,
			    restriction_no,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "CMK_SetRestriction");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */

	ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, 0, 0);

	return ret;
}

uint32_t
TPM_CMK_ApproveMA(unsigned char *migAuthDigest, 
                  unsigned char *ownerAuth, 
                  unsigned char *hmac)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CMK_ApproveMA);
	uint32_t ret;
	session sess;

	/* check input arguments */
	if (NULL == ownerAuth)
		return ERR_NULL_ARG;

	/* generate odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (0 == ret)
		return ERR_CRYPT_ERR;

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
			      &sess, ownerAuth, TPM_ET_OWNER, 0);
	if (ret != 0)
		return ret;

	ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c,
			   TPM_U32_SIZE, &ordinal_no, TPM_DIGEST_SIZE,
			   migAuthDigest, 0, 0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l % L % o %", &tpmdata,
			    ordinal_no,
			    TPM_DIGEST_SIZE, migAuthDigest,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "CMK_ApproveMA - AUTH1");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */
	ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			     TPM_HASH_SIZE, TPM_DATA_OFFSET, 0, 0);

	if (ret != 0) {
		return ret;
	}

	if (NULL != hmac) {
		memcpy(hmac, &tpmdata.buffer[TPM_DATA_OFFSET], TPM_HASH_SIZE);
	}

	return ret;
}

uint32_t
TPM_CMK_CreateKey(uint32_t parenthandle,
		  unsigned char *parkeyUsageAuth,
		  unsigned char *dataUsageAuth,
		  keydata * keyRequest,
		  unsigned char *migAuthApproval,
		  unsigned char *migAuthDigest,
		  keydata * key, unsigned char *blob, uint32_t * bloblen)
{
	uint32_t ret = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CMK_CreateKey);
	unsigned char c = 0;

	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char encauth[TPM_NONCE_SIZE];

	STACK_TPM_BUFFER(kparmbuf)
	unsigned char dummy[TPM_HASH_SIZE];
	uint32_t parenthandle_no = htonl(parenthandle);
	session sess;
	unsigned char *usagehashptr = NULL;

	uint32_t keylen;
	uint16_t keytype;
	uint32_t kparmbufsize;

	if (NULL == parkeyUsageAuth ||
	    NULL == keyRequest ||
	    NULL == migAuthApproval || NULL == migAuthDigest) {
		return ERR_NULL_ARG;
	}

	memset(dummy, 0x0, sizeof (dummy));

	if (parenthandle == 0x40000000)
		keytype = TPM_ET_SRK;
	else
		keytype = TPM_ET_KEYHANDLE;

	ret = needKeysRoom(parenthandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	TSS_gennonce(nonceodd);

	ret = TPM_WriteKey(&kparmbuf, keyRequest);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	kparmbufsize = ret;

	/*
	 * Open OSAP session
	 */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP,&sess, parkeyUsageAuth, keytype, parenthandle);
	if (0 != ret) {
		return ret;
	}

	/* Generate the encrypted usage authorization */

	if (NULL != dataUsageAuth) {
		usagehashptr = dataUsageAuth;
	} else {
		usagehashptr = dummy;
	}

	TPM_CreateEncAuth(&sess, usagehashptr, encauth, 0);

	ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess), TPM_HASH_SIZE, TSS_Session_GetENonce(&sess),
			   nonceodd, c, 
			   TPM_U32_SIZE, &ordinal_no,
			   TPM_HASH_SIZE, encauth, 
			   kparmbufsize, kparmbuf.buffer, 
			   TPM_DIGEST_SIZE, migAuthApproval,
			   TPM_DIGEST_SIZE, migAuthDigest, 
			   0, 0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = TSS_buildbuff("00 c2 T l l % % % % L % o %", &tpmdata,
			    ordinal_no,
			    parenthandle_no,
			    TPM_HASH_SIZE, encauth,
			    kparmbufsize, kparmbuf.buffer,
			    TPM_DIGEST_SIZE, migAuthApproval,
			    TPM_DIGEST_SIZE, migAuthDigest,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);

	if (ret <= 0) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata, "CMK_CreateKey - AUTH1");
	TSS_SessionClose(&sess);

	if (0 != ret) {
		return ret;
	}

	keylen = TSS_KeyExtract(&tpmdata, TPM_DATA_OFFSET, key);

	ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd, TSS_Session_GetAuth(&sess),
			     TPM_HASH_SIZE, keylen, TPM_DATA_OFFSET, 0, 0);
	if (0 != ret) {
		return ret;
	}
	/*
	 * Have to deserialize the key
	 */

	if (NULL != blob) {
		*bloblen = MIN(*bloblen, keylen);
		memcpy(blob, &tpmdata.buffer[TPM_DATA_OFFSET], *bloblen);
	}

	return ret;
}

uint32_t
TPM_CMK_CreateTicket(keydata * key,
		     unsigned char *signedData,
		     unsigned char *signatureValue, uint32_t signatureValueSize,
		     unsigned char *ownerAuth, 
		     unsigned char *ticketBuf)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CMK_CreateTicket);
	uint32_t ret;
	uint32_t signatureValueSize_no = htonl(signatureValueSize);

	STACK_TPM_BUFFER(serPubKey)
	uint32_t serPubKeySize;
	session sess;

	/* check input arguments */
	if (NULL == ownerAuth ||
	    NULL == signedData || NULL == signatureValue || NULL == key)
		return ERR_NULL_ARG;

	ret = TPM_WriteKeyPub(&serPubKey, key);
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}
	serPubKeySize = ret;

	/* generate odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (0 == ret) {
		return ERR_CRYPT_ERR;
	}

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP | SESSION_OIAP,
			      &sess, ownerAuth, TPM_ET_OWNER, 0);
	if (ret != 0) {
		return ret;
	}

	ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c,
			   TPM_U32_SIZE, &ordinal_no,
			   serPubKeySize, serPubKey.buffer,
			   TPM_DIGEST_SIZE, signedData,
			   TPM_U32_SIZE, &signatureValueSize_no,
			   signatureValueSize, signatureValue,
			   0, 0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l % % @ L % o %", &tpmdata,
			             ordinal_no,
				       serPubKeySize, serPubKey.buffer,
			                 TPM_DIGEST_SIZE, signedData,
			                   signatureValueSize, signatureValue,
			                     TSS_Session_GetHandle(&sess),
			                       TPM_NONCE_SIZE, nonceodd,
			                         c,
			                           TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata, "CMK_CreateTicket - AUTH1");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */

	ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			     TPM_DIGEST_SIZE, TPM_DATA_OFFSET, 0, 0);

	if (NULL != ticketBuf) {
		memcpy(ticketBuf,
		       &tpmdata.buffer[TPM_DATA_OFFSET], TPM_DIGEST_SIZE);
	}

	return ret;
}

uint32_t
TPM_CMK_CreateBlob(uint32_t parenthandle,
		   unsigned char *parkeyUsageAuth,
		   uint16_t migScheme,
		   const struct tpm_buffer *migblob,
		   unsigned char *sourceKeyDigest,
		   TPM_MSA_COMPOSITE * msaList,
		   TPM_CMK_AUTH * resTicket,
		   unsigned char *sigTicket, uint32_t sigTicketSize,
		   unsigned char *encData, uint32_t encDataSize,
		   unsigned char *random, uint32_t * randomSize,
		   unsigned char *outData, uint32_t * outDataSize)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CMK_CreateBlob);
	uint32_t ret;
	uint32_t parenthandle_no = htonl(parenthandle);
	uint16_t migScheme_no = htons(migScheme);
	uint32_t sigTicketSize_no = htonl(sigTicketSize);
	uint32_t encDataSize_no = htonl(encDataSize);
	uint32_t len1;
	uint32_t len2;
	uint32_t serMsaListSize = 0;
	uint32_t serMsaListSize_no;
	struct tpm_buffer *serMsaList;
	session sess;
	unsigned char dummyauth[TPM_HASH_SIZE];

	memset(dummyauth,0,sizeof dummyauth);

	STACK_TPM_BUFFER(serResTicket)
	uint32_t serResTicketSize = 0;
	uint32_t serResTicketSize_no = 0;
	
	if (parkeyUsageAuth == NULL)
		parkeyUsageAuth = dummyauth;

	/* check input arguments */
	if (encData == NULL ||
	    outData == NULL ||
	    (sigTicket == NULL && sigTicketSize != 0) || msaList == NULL)
		return ERR_NULL_ARG;

	/* TPM_MS_RESTRICT_APPROVE needs restrictTicket, TPM_MS_RESTRICT_MIGRATE does not */
	if ((migScheme == TPM_MS_RESTRICT_APPROVE) &&
	    (resTicket == NULL)) {
	    return ERR_NULL_ARG;
	}


	ret = needKeysRoom(parenthandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	serMsaList =
		TSS_AllocTPMBuffer(msaList->MSAlist * TPM_HASH_SIZE +
				   TPM_U32_SIZE);
	serMsaListSize = TPM_WriteMSAComposite(serMsaList, msaList);
	serMsaListSize_no = htonl(serMsaListSize);

	if (NULL != resTicket) {
		ret = TPM_WriteCMKAuth(&serResTicket, resTicket);
		if ((ret & ERR_MASK) != 0) {
			return ret;
		}
		serResTicketSize = ret;
		serResTicketSize_no = htonl(serResTicketSize);
	}

	/* generate odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (0 == ret) {
		TSS_FreeTPMBuffer(serMsaList);
		return ERR_CRYPT_ERR;
	}
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP | SESSION_DSAP,
			      &sess, parkeyUsageAuth, TPM_ET_KEYHANDLE, parenthandle);
	if (ret != 0) {
		TSS_FreeTPMBuffer(serMsaList);
		return ret;
	}
	/* move Network byte order data to variable for hmac calculation */

	if (0 != serResTicketSize && 0 != sigTicketSize) {

		ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess),
				   TPM_HASH_SIZE, TSS_Session_GetENonce(&sess),
				   nonceodd, c, TPM_U32_SIZE, &ordinal_no,
				   TPM_U16_SIZE, &migScheme_no, migblob->used,
				   migblob->buffer, TPM_DIGEST_SIZE, sourceKeyDigest,
				   TPM_U32_SIZE, &serMsaListSize_no,
				   serMsaListSize, serMsaList->buffer,
				   TPM_U32_SIZE, &serResTicketSize_no,
				   serResTicketSize, serResTicket.buffer,
				   TPM_U32_SIZE, &sigTicketSize_no,
				   sigTicketSize, sigTicket, TPM_U32_SIZE,
				   &encDataSize_no, encDataSize, encData, 0,
				   0);
	} else {
		if (0 == serResTicketSize && 0 == sigTicketSize) {
			ret = TSS_authhmac(authdata,
					   TSS_Session_GetAuth(&sess),
					   TPM_HASH_SIZE,
					   TSS_Session_GetENonce(&sess),
					   nonceodd, c, TPM_U32_SIZE,
					   &ordinal_no, TPM_U16_SIZE,
					   &migScheme_no, migblob->used, migblob->buffer,
					   TPM_DIGEST_SIZE, sourceKeyDigest,
					   TPM_U32_SIZE, &serMsaListSize_no,
					   serMsaListSize, serMsaList->buffer,
					   TPM_U32_SIZE, &serResTicketSize_no,
					   // would be 0,0   resTicketSize, resTicket,
					   TPM_U32_SIZE, &sigTicketSize_no,
					   // would be 0,0   sigTicketSize, sigTicket,
					   TPM_U32_SIZE, &encDataSize_no,
					   encDataSize, encData, 0, 0);
		} else if (0 != sigTicketSize) {
			ret = TSS_authhmac(authdata,
					   TSS_Session_GetAuth(&sess),
					   TPM_HASH_SIZE,
					   TSS_Session_GetENonce(&sess),
					   nonceodd, c, TPM_U32_SIZE,
					   &ordinal_no, TPM_U16_SIZE,
					   &migScheme_no, migblob->used, migblob->buffer,
					   TPM_DIGEST_SIZE, sourceKeyDigest,
					   TPM_U32_SIZE, &serMsaListSize_no,
					   serMsaListSize, serMsaList->buffer,
					   TPM_U32_SIZE, &serResTicketSize_no,
					   // would be 0,0   resTicketSize, resTicket,
					   TPM_U32_SIZE, &sigTicketSize_no,
					   sigTicketSize, sigTicket,
					   TPM_U32_SIZE, &encDataSize_no,
					   encDataSize, encData, 0, 0);
		} else if (0 != serResTicketSize) {
			ret = TSS_authhmac(authdata,
					   TSS_Session_GetAuth(&sess),
					   TPM_HASH_SIZE,
					   TSS_Session_GetENonce(&sess),
					   nonceodd, c, TPM_U32_SIZE,
					   &ordinal_no, TPM_U16_SIZE,
					   &migScheme_no, migblob->used, migblob->buffer,
					   TPM_DIGEST_SIZE, sourceKeyDigest,
					   TPM_U32_SIZE, &serMsaListSize_no,
					   serMsaListSize, serMsaList->buffer,
					   TPM_U32_SIZE, &serResTicketSize_no,
					   serResTicketSize,
					   serResTicket.buffer, TPM_U32_SIZE,
					   &sigTicketSize_no,
					   // would be 0,0 sigTicketSize, sigTicket,
					   TPM_U32_SIZE, &encDataSize_no,
					   encDataSize, encData, 0, 0);
		}
	}
	if (0 != ret) {
		TSS_FreeTPMBuffer(serMsaList);
		TSS_SessionClose(&sess);
		return ret;
	}

	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l s % % @ @ @ @ L % o %", &tpmdata,
			    ordinal_no,
			    parenthandle_no,
			    migScheme_no,
			    migblob->used, migblob->buffer,
			    TPM_DIGEST_SIZE, sourceKeyDigest,
			    serMsaListSize, serMsaList->buffer,
			    serResTicketSize, serResTicket.buffer,
			    sigTicketSize, sigTicket,
			    encDataSize, encData,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);

	if ((ret & ERR_MASK)) {
		TSS_FreeTPMBuffer(serMsaList);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata, "CMK_CreateBlob - AUTH1");

	TSS_FreeTPMBuffer(serMsaList);
	TSS_SessionClose(&sess);

	if (0 != ret) {
		return ret;
	}

	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len1);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + TPM_U32_SIZE + len1, &len2);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			     TPM_U32_SIZE + len1 + TPM_U32_SIZE + len2,
			     TPM_DATA_OFFSET, 0, 0);

	if (0 != ret) {
		return ret;
	}

	if (NULL != random) {
		*randomSize = MIN(*randomSize, len1);
		memcpy(random,
		       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
		       *randomSize);
	}

	if (NULL != outData) {
		*outDataSize = MIN(*outDataSize, len2);
		memcpy(outData,
		       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE + len1 +
				       TPM_U32_SIZE], *outDataSize);
	}

	return ret;
}

uint32_t
TPM_CMK_ConvertMigration(uint32_t parenthandle,
			 unsigned char *parkeyUsageAuth,
			 TPM_CMK_AUTH * resTicket,
			 unsigned char *sigTicket,
			 keydata * migratedKey,
			 TPM_MSA_COMPOSITE * msaList,
			 unsigned char *random, uint32_t randomSize,
			 unsigned char *outData, uint32_t * outDataSize)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_CMK_ConvertMigration);
	uint32_t ret;
	uint32_t parenthandle_no = htonl(parenthandle);
	uint32_t randomSize_no = htonl(randomSize);
	uint32_t len1;

	STACK_TPM_BUFFER(serResTicket)
	uint32_t serResTicketSize = sizeof (serResTicket);

	uint32_t serMsaListSize =
		TPM_U32_SIZE + msaList->MSAlist * TPM_HASH_SIZE;
	uint32_t serMsaListSize_no = htonl(serMsaListSize);
	struct tpm_buffer *serMsaList;
	session sess;

	STACK_TPM_BUFFER(serMigratedKey)
	uint32_t serMigratedKeySize;
	unsigned char dummyauth[TPM_HASH_SIZE];

	memset(dummyauth,0,sizeof dummyauth);
	
	if (parkeyUsageAuth == NULL)
		parkeyUsageAuth = dummyauth;

	/* check input arguments */
	if (NULL == migratedKey || NULL == msaList || NULL == sigTicket)
		return ERR_NULL_ARG;

	ret = needKeysRoom(parenthandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	ret = TPM_WriteKey(&serMigratedKey, migratedKey);
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}
	serMigratedKeySize = ret;

	ret = TPM_WriteCMKAuth(&serResTicket, resTicket);
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}
	serResTicketSize = ret;

	serMsaList = TSS_AllocTPMBuffer(serMsaListSize);
	if (NULL == serMsaList)
		return ERR_MEM_ERR;
	/*
	 * Serialize the MSA list
	 */
	ret = TPM_WriteMSAComposite(serMsaList, msaList);
	if ((ret & ERR_MASK) != 0) {
		TSS_FreeTPMBuffer(serMsaList);
		return ret;
	}
	serMsaListSize = ret;
	serMsaListSize_no = htonl(serMsaListSize);

	/* generate odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (0 == ret) {
		TSS_FreeTPMBuffer(serMsaList);
		return ERR_CRYPT_ERR;
	}
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP | SESSION_OIAP,
			      &sess,
			      parkeyUsageAuth, TPM_ET_KEYHANDLE, parenthandle);
	if (ret != 0) {
		TSS_FreeTPMBuffer(serMsaList);
		return ret;
	}
	/* move Network byte order data to variable for hmac calculation */
	ret = TSS_authhmac(authdata, TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			   TSS_Session_GetENonce(&sess), nonceodd, c,
			   TPM_U32_SIZE, &ordinal_no, serResTicketSize,
			   serResTicket.buffer, TPM_HASH_SIZE, sigTicket,
			   serMigratedKeySize, serMigratedKey.buffer,
			   TPM_U32_SIZE, &serMsaListSize_no, serMsaListSize,
			   serMsaList->buffer, TPM_U32_SIZE, &randomSize_no,
			   randomSize, random, 0, 0);
	if (0 != ret) {
		TSS_FreeTPMBuffer(serMsaList);
		TSS_SessionClose(&sess);
		return ret;
	}

	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l % % % @ @ L % o %", &tpmdata,
			    ordinal_no,
			    parenthandle_no,
			    serResTicketSize, serResTicket.buffer,
			    TPM_DIGEST_SIZE, sigTicket,
			    serMigratedKeySize, serMigratedKey.buffer,
			    serMsaListSize, serMsaList->buffer,
			    randomSize, random,
			    TSS_Session_GetHandle(&sess),
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);

	TSS_FreeTPMBuffer(serMsaList);

	if ((ret & ERR_MASK)) {
		return ret;
	}

	ret = TPM_Transmit(&tpmdata, "CMK_ConvertMigration - AUTH1");

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len1);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata, ordinal_no, nonceodd,
			     TSS_Session_GetAuth(&sess), TPM_HASH_SIZE,
			     TPM_U32_SIZE + len1, TPM_DATA_OFFSET, 0, 0);

	if (0 != ret) {
		return ret;
	}

	if (NULL != outData) {
		*outDataSize = MIN(*outDataSize, len1);
		memcpy(outData,
		       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
		       *outDataSize);
	}

	return ret;
}
