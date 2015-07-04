/*
 * libtpm: auth routines
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <tpm.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tpmkeys.h>

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
uint32_t TPM_ChangeAuth(uint32_t keyhandle,
			unsigned char *parauth,
			unsigned char *keyauth,
			unsigned char *newauth, keydata * key)
{
	unsigned char chgauth_fmt[] =
	    "00 C3 T l l s % s @ l % o % l % o %";
	uint32_t ret;
	int i;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	uint32_t authhandle2;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char xorwork[TPM_HASH_SIZE + TPM_NONCE_SIZE];
	unsigned char xorhash[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char enonce2[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint16_t protocol;
	uint16_t entitytype;
	uint32_t keysize;
	uint32_t keyhndl;
	uint16_t keytype;
	int reslen;

	/* check input arguments */
	if (parauth == NULL || keyauth == NULL || newauth == NULL
	    || key == NULL)
		return ERR_NULL_ARG;
	if (keyhandle == 0x40000000)
		keytype = 0x0004;
	else
		keytype = 0x0001;
	/* open OSAP session for parent key auth */
	ret = TSS_OSAPopen(&sess, parauth, keytype, keyhandle);
	if (ret != 0)
		return ret;
	/* open OIAP session for existing key auth */
	ret = TSS_OIAPopen(&authhandle2, enonce2);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value for OSAP session */
	memcpy(xorwork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorwork + TPM_HASH_SIZE, sess.enonce, TPM_NONCE_SIZE);
	TSS_sha1(xorwork, TPM_HASH_SIZE + TPM_NONCE_SIZE, xorhash);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x0C);
	protocol = htons(0x0004);
	entitytype = htons(0x0005);
	keysize = htonl(key->privkeylen);
	keyhndl = htonl(keyhandle);
	c = 0;
	/* encrypt new key auth data */
	for (i = 0; i < TPM_HASH_SIZE; ++i)
		encauth[i] = xorhash[i] ^ newauth[i];
	/* calculate OSAP authorization HMAC value */
	ret =
	    TSS_authhmac(authdata1, sess.ssecret, TPM_NONCE_SIZE,
			 sess.enonce, nonceodd, c, TPM_U32_SIZE, &ordinal,
			 TPM_U16_SIZE, &protocol, TPM_HASH_SIZE, encauth,
			 TPM_U16_SIZE, &entitytype, TPM_U32_SIZE, &keysize,
			 key->privkeylen, key->encprivkey, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		TSS_OIAPclose(authhandle2);
		return ret;
	}
	/* calculate OIAP authorization HMAC value */
	ret =
	    TSS_authhmac(authdata2, keyauth, TPM_NONCE_SIZE, enonce2,
			 nonceodd, c, TPM_U32_SIZE, &ordinal, TPM_U16_SIZE,
			 &protocol, TPM_HASH_SIZE, encauth, TPM_U16_SIZE,
			 &entitytype, TPM_U32_SIZE, &keysize,
			 key->privkeylen, key->encprivkey, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		TSS_OIAPclose(authhandle2);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(chgauth_fmt, tpmdata,
			    ordinal,
			    keyhndl,
			    protocol,
			    TPM_HASH_SIZE, encauth,
			    entitytype,
			    key->privkeylen, key->encprivkey,
			    sess.handle,
			    TPM_NONCE_SIZE, nonceodd,
			    c,
			    TPM_HASH_SIZE, authdata1,
			    authhandle2,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata2);

	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		TSS_OIAPclose(authhandle2);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "ChangeAuth");
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		TSS_OIAPclose(authhandle2);
		return ret;
	}
	reslen = LOAD32(tpmdata, TPM_DATA_OFFSET);
	/* check HMAC in response */
	ret = TSS_checkhmac2(tpmdata, ordinal, nonceodd,
			     sess.ssecret, TPM_HASH_SIZE,
			     keyauth, TPM_HASH_SIZE,
			     TPM_U32_SIZE, TPM_DATA_OFFSET,
			     reslen, TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
	TSS_OSAPclose(&sess);
	TSS_OIAPclose(authhandle2);
	if (ret != 0)
		return ret;
	/* copy updated key blob back to caller */
	memcpy(key->encprivkey, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE,
	       reslen);
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
uint32_t TPM_ChangeSRKAuth(unsigned char *ownauth, unsigned char *newauth)
{
	unsigned char chgsrkauth_fmt[] = "00 C2 T l s % s l % o %";
	uint32_t ret;
	int i;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char xorwork[TPM_HASH_SIZE + TPM_NONCE_SIZE];
	unsigned char xorhash[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint16_t protocol;
	uint16_t entitytype;

	/* check input arguments */
	if (ownauth == NULL || newauth == NULL)
		return ERR_NULL_ARG;
	/* open OSAP session for owner auth */
	ret = TSS_OSAPopen(&sess, ownauth, 0x0002, 0);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value for OSAP session */
	memcpy(xorwork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorwork + TPM_HASH_SIZE, sess.enonce, TPM_NONCE_SIZE);
	TSS_sha1(xorwork, TPM_HASH_SIZE + TPM_NONCE_SIZE, xorhash);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x10);
	protocol = htons(0x0004);
	entitytype = htons(0x0004);
	c = 0;
	/* encrypt new SRK auth data */
	for (i = 0; i < TPM_HASH_SIZE; ++i)
		encauth[i] = xorhash[i] ^ newauth[i];
	/* calculate OSAP authorization HMAC value */
	ret =
	    TSS_authhmac(authdata1, sess.ssecret, TPM_NONCE_SIZE,
			 sess.enonce, nonceodd, c, TPM_U32_SIZE, &ordinal,
			 TPM_U16_SIZE, &protocol, TPM_HASH_SIZE, encauth,
			 TPM_U16_SIZE, &entitytype, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(chgsrkauth_fmt, tpmdata,
			    ordinal,
			    protocol,
			    TPM_HASH_SIZE, encauth,
			    entitytype,
			    sess.handle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata1);

	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "ChangeSRKAuth");
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac1(tpmdata, ordinal, nonceodd,
			     sess.ssecret, TPM_HASH_SIZE, 0, 0);
	TSS_OSAPclose(&sess);
	if (ret != 0)
		return ret;
	return 0;
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
uint32_t TPM_ChangeOwnAuth(unsigned char *ownauth, unsigned char *newauth)
{
	unsigned char chgownauth_fmt[] = "00 C2 T l s % s l % o %";
	uint32_t ret;
	int i;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char xorwork[TPM_HASH_SIZE + TPM_NONCE_SIZE];
	unsigned char xorhash[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint16_t protocol;
	uint16_t entitytype;

	/* check input arguments */
	if (ownauth == NULL || newauth == NULL)
		return ERR_NULL_ARG;
	/* open OSAP session for owner auth */
	ret = TSS_OSAPopen(&sess, ownauth, 0x0002, 0);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value for OSAP session */
	memcpy(xorwork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorwork + TPM_HASH_SIZE, sess.enonce, TPM_NONCE_SIZE);
	TSS_sha1(xorwork, TPM_HASH_SIZE + TPM_NONCE_SIZE, xorhash);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x10);
	protocol = htons(0x0004);
	entitytype = htons(0x0002);
	c = 0;
	/* encrypt new Owner auth data */
	for (i = 0; i < TPM_HASH_SIZE; ++i)
		encauth[i] = xorhash[i] ^ newauth[i];
	/* calculate OSAP authorization HMAC value */
	ret =
	    TSS_authhmac(authdata1, sess.ssecret, TPM_NONCE_SIZE,
			 sess.enonce, nonceodd, c, TPM_U32_SIZE, &ordinal,
			 TPM_U16_SIZE, &protocol, TPM_HASH_SIZE, encauth,
			 TPM_U16_SIZE, &entitytype, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(chgownauth_fmt, tpmdata,
			    ordinal,
			    protocol,
			    TPM_HASH_SIZE, encauth,
			    entitytype,
			    sess.handle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata1);

	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "ChangeOwnAuth");
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* check HMAC in response */
	ret = TSS_checkhmac1(tpmdata, ordinal, nonceodd,
			     sess.ssecret, TPM_HASH_SIZE, 0, 0);
	TSS_OSAPclose(&sess);
	if (ret != 0)
		return ret;
	return 0;
}
