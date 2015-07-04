/*
 * libtpm: key handling routines
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
#include <tpmfunc.h>
#include <tpmutil.h>
#include <tpmkeys.h>
#include <oiaposap.h>
#include <hmac.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

/****************************************************************************/
/*                                                                          */
/* Read the TPM Endorsement public key                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_ReadPubek(pubkeydata * k)
{
	unsigned char read_pubek_fmt[] = "00 c1 T 00 00 00 7c %";
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonce[TPM_HASH_SIZE];
	uint32_t ret;

	/* check input argument */
	if (k == NULL)
		return ERR_NULL_ARG;
	/* generate random nonce */
	ret = TSS_gennonce(nonce);
	if (ret == 0)
		return ERR_CRYPT_ERR;
	/* copy Read PubKey request template to buffer */
	ret = TSS_buildbuff(read_pubek_fmt, tpmdata, TPM_HASH_SIZE, nonce);
	if ((ret & ERR_MASK) != 0)
		return ret;
	ret = TPM_Transmit(tpmdata, "tpm_readpubek");
	if (ret)
		return ret;
	TSS_PubKeyExtract(tpmdata + TPM_DATA_OFFSET, k, 0);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Owner Read the TPM Endorsement Key                                       */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OwnerReadPubek(unsigned char *ownauth, pubkeydata * k)
{
	unsigned char owner_read_ekey_fmt[] = "00 c2 T l l % o %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t authhandle;
	int size;

	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* Open OIAP Session */
	ret = TSS_OIAPopen(&authhandle, evennonce);
	if (ret != 0)
		return ret;
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x7D);
	c = 0;
	/* calculate authorization HMAC value */
	ret =
	    TSS_authhmac(authdata, ownauth, TPM_HASH_SIZE, evennonce,
			 nonceodd, c, TPM_U32_SIZE, &ordinal, 0, 0);
	if (ret < 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(owner_read_ekey_fmt, tpmdata,
			    ordinal,
			    authhandle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "OwnerReadEkey");
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	TSS_OIAPclose(authhandle);
	size = TSS_PubKeySize(tpmdata + TPM_DATA_OFFSET, 0);
	ret =
	    TSS_checkhmac1(tpmdata, ordinal, nonceodd, ownauth,
			   TPM_HASH_SIZE, size, TPM_DATA_OFFSET, 0, 0);
	if (ret != 0)
		return ret;
	TSS_PubKeyExtract(tpmdata + TPM_DATA_OFFSET, k, 0);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Disable Reading of the Public Encorsement Key                            */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_DisableReadPubek(unsigned char *ownauth)
{
	unsigned char disable_ekey_fmt[] = "00 c2 T l l % o %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t authhandle;

	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* Open OIAP Session */
	ret = TSS_OIAPopen(&authhandle, evennonce);
	if (ret != 0)
		return ret;
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x7E);
	c = 0;
	/* calculate authorization HMAC value */
	ret =
	    TSS_authhmac(authdata, ownauth, TPM_HASH_SIZE, evennonce,
			 nonceodd, c, TPM_U32_SIZE, &ordinal, 0, 0);
	if (ret < 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(disable_ekey_fmt, tpmdata,
			    ordinal,
			    authhandle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "DisableEkey");
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	TSS_OIAPclose(authhandle);
	ret =
	    TSS_checkhmac1(tpmdata, ordinal, nonceodd, ownauth,
			   TPM_HASH_SIZE, 0, 0);
	if (ret != 0)
		return ret;
	return 0;
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
			   keydata * keyparms,
			   keydata * key,
			   unsigned char *keyblob, unsigned int *bloblen)
{
	unsigned char create_key_fmt[] = "00 c2 T l l % % % l % o %";
	uint32_t ret;
	int i;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char kparmbuf[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	unsigned char encauth1[TPM_HASH_SIZE];
	unsigned char encauth2[TPM_HASH_SIZE];
	unsigned char xorwork[TPM_HASH_SIZE * 2];
	unsigned char xorhash[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char dummyauth[TPM_HASH_SIZE];
	unsigned char *cparauth;
	unsigned char *cnewauth;
	unsigned char c;
	uint32_t ordinal;
	uint32_t keyhndl;
	uint16_t keytype;
	int kparmbufsize;

	memset(dummyauth, 0, sizeof dummyauth);
	/* check input arguments */
	if (keyparms == NULL)
		return ERR_NULL_ARG;
	if (parauth == NULL)
		cparauth = dummyauth;
	else
		cparauth = parauth;
	if (newauth == NULL)
		cnewauth = dummyauth;
	else
		cnewauth = newauth;
	if (keyhandle == 0x40000000)
		keytype = 0x0004;
	else
		keytype = 0x0001;
	/* get the TPM version and put into the keyparms structure */
	ret =
	    TPM_GetCapability(0x00000006, NULL, 0, &(keyparms->version[0]),
			      &i);
	if (ret != 0)
		return ret;
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* Open OSAP Session */
	ret = TSS_OSAPopen(&sess, cparauth, keytype, keyhandle);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value for new key */
	memcpy(xorwork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorwork + TPM_HASH_SIZE, sess.enonce, TPM_HASH_SIZE);
	TSS_sha1(xorwork, TPM_HASH_SIZE * 2, xorhash);
	for (i = 0; i < TPM_HASH_SIZE; ++i)
		encauth1[i] = xorhash[i] ^ cnewauth[i];
	/* calculate encrypted authorization value for migration of new key */
	if (migauth != NULL) {
		memcpy(xorwork, sess.ssecret, TPM_HASH_SIZE);
		memcpy(xorwork + TPM_HASH_SIZE, nonceodd, TPM_HASH_SIZE);
		TSS_sha1(xorwork, TPM_HASH_SIZE * 2, xorhash);
		for (i = 0; i < TPM_HASH_SIZE; ++i)
			encauth2[i] = xorhash[i] ^ migauth[i];
	} else
		memset(encauth2, 0, TPM_HASH_SIZE);
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x1F);
	keyhndl = htonl(keyhandle);
	c = 0;
	/* convert keyparm structure to buffer */
	ret = TPM_BuildKey(kparmbuf, keyparms);
	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	kparmbufsize = ret;
	/* calculate authorization HMAC value */
	ret =
	    TSS_authhmac(pubauth, sess.ssecret, TPM_HASH_SIZE, sess.enonce,
			 nonceodd, c, TPM_U32_SIZE, &ordinal,
			 TPM_HASH_SIZE, encauth1, TPM_HASH_SIZE, encauth2,
			 kparmbufsize, kparmbuf, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(create_key_fmt, tpmdata,
			    ordinal,
			    keyhndl,
			    TPM_HASH_SIZE, encauth1,
			    TPM_HASH_SIZE, encauth2,
			    kparmbufsize, kparmbuf,
			    sess.handle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "CreateWrapKey");
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	kparmbufsize = TSS_KeySize(tpmdata + TPM_DATA_OFFSET);
	ret =
	    TSS_checkhmac1(tpmdata, ordinal, nonceodd, sess.ssecret,
			   TPM_HASH_SIZE, kparmbufsize, TPM_DATA_OFFSET, 0,
			   0);
	TSS_OSAPclose(&sess);
	if (ret != 0)
		return ret;
	/* convert the returned key to a structure */
	if (key != NULL)
		TSS_KeyExtract(tpmdata + TPM_DATA_OFFSET, key);
	/* copy the key blob to caller */
	if (keyblob != NULL) {
		memcpy(keyblob, tpmdata + TPM_DATA_OFFSET, kparmbufsize);
		if (bloblen != NULL)
			*bloblen = kparmbufsize;
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
		     keydata * keyparms, uint32_t * newhandle)
{
	unsigned char load_key_fmt[] = "00 c2 T l l % l % o %";
	unsigned char load_key_fmt_noauth[] = "00 c1 T l l %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char kparmbuf[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t keyhndl;
	uint32_t authhandle;
	int kparmbufsize;

	/* check input arguments */
	if (keyparms == NULL || newhandle == NULL)
		return ERR_NULL_ARG;
	if (keyauth != NULL) {	/* parent requires authorization */
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Open OIAP Session */
		ret = TSS_OIAPopen(&authhandle, evennonce);
		if (ret != 0)
			return ret;
		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x20);
		keyhndl = htonl(keyhandle);
		c = 0;
		/* convert keyparm structure to buffer */
		ret = TPM_BuildKey(kparmbuf, keyparms);
		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		kparmbufsize = ret;
		/* calculate authorization HMAC value */
		ret =
		    TSS_authhmac(pubauth, keyauth, TPM_HASH_SIZE,
				 evennonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, kparmbufsize, kparmbuf, 0, 0);
		if (ret < 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(load_key_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    kparmbufsize, kparmbuf,
				    authhandle,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "LoadKey");
		if (ret != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		TSS_OIAPclose(authhandle);
		ret =
		    TSS_checkhmac1(tpmdata, ordinal, nonceodd, keyauth,
				   TPM_HASH_SIZE, TPM_U32_SIZE,
				   TPM_DATA_OFFSET, 0, 0);
		if (ret != 0)
			return ret;
		*newhandle = LOAD32(tpmdata, TPM_DATA_OFFSET);
	} else {		/* parent requires NO authorization */

		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x20);
		keyhndl = htonl(keyhandle);
		/* convert keyparm structure to buffer */
		ret = TPM_BuildKey(kparmbuf, keyparms);
		if ((ret & ERR_MASK) != 0)
			return ret;
		kparmbufsize = ret;
		/* build the request buffer */
		ret = TSS_buildbuff(load_key_fmt_noauth, tpmdata,
				    ordinal,
				    keyhndl, kparmbufsize, kparmbuf);
		if ((ret & ERR_MASK) != 0)
			return ret;
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "LoadKey");
		if (ret != 0)
			return ret;
		*newhandle = LOAD32(tpmdata, TPM_DATA_OFFSET);
	}
	return 0;
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
uint32_t TPM_GetPubKey(uint32_t keyhandle,
		       unsigned char *keyauth,
		       unsigned char *keyblob, unsigned int *keyblen)
{
	unsigned char getpub_key_fmt[] = "00 c2 T l l l % o %";
	unsigned char getpub_key_fmt_noauth[] = "00 c1 T l l";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t keyhndl;
	uint32_t authhandle;
	int size;

	/* check input arguments */
	if (keyblob == NULL || keyblen == NULL)
		return ERR_NULL_ARG;
	if (keyauth != NULL) {	/* key requires authorization */
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Open OIAP Session */
		ret = TSS_OIAPopen(&authhandle, evennonce);
		if (ret != 0)
			return ret;
		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x21);
		keyhndl = htonl(keyhandle);
		c = 0;
		/* calculate authorization HMAC value */
		ret =
		    TSS_authhmac(pubauth, keyauth, TPM_HASH_SIZE,
				 evennonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(getpub_key_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    authhandle,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "GetPubKey");
		if (ret != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		TSS_OIAPclose(authhandle);
		size = TSS_PubKeySize(tpmdata + TPM_DATA_OFFSET, 0);
		ret =
		    TSS_checkhmac1(tpmdata, ordinal, nonceodd, keyauth,
				   TPM_HASH_SIZE, size, TPM_DATA_OFFSET, 0,
				   0);
		if (ret != 0)
			return ret;
		memcpy(keyblob, tpmdata + TPM_DATA_OFFSET, size);
		*keyblen = size;
	} else {		/* key requires NO authorization */

		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x21);
		keyhndl = htonl(keyhandle);
		/* build the request buffer */
		ret = TSS_buildbuff(getpub_key_fmt_noauth, tpmdata,
				    ordinal, keyhndl);
		if ((ret & ERR_MASK) != 0)
			return ret;
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "GetPubKey");
		if (ret != 0)
			return ret;
		size = TSS_PubKeySize(tpmdata + TPM_DATA_OFFSET, 0);
		memcpy(keyblob, tpmdata + TPM_DATA_OFFSET, size);
		*keyblen = size;
	}
	return 0;
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
uint32_t TPM_EvictKey(uint32_t keyhandle)
{
	unsigned char evict_key_fmt[] = "00 c1 T 00 00 00 22 L";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];

	ret = TSS_buildbuff(evict_key_fmt, tpmdata, keyhandle);
	if ((ret & ERR_MASK) != 0)
		return ret;
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "EvictKey");
	if (ret != 0)
		return ret;
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Create a buffer from a keydata structure                                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_BuildKey(unsigned char *buffer, keydata * k)
{
	unsigned char build_key_fmt[] = "% S L o L S S L L L L @ @ @";
	uint32_t ret;

	ret = TSS_buildbuff(build_key_fmt, buffer,
			    4, k->version,
			    k->keyusage,
			    k->keyflags,
			    k->authdatausage,
			    k->pub.algorithm,
			    k->pub.encscheme,
			    k->pub.sigscheme,
			    12,
			    k->pub.keybitlen,
			    k->pub.numprimes,
			    0,
			    k->pub.pcrinfolen, k->pub.pcrinfo,
			    k->pub.keylength, k->pub.modulus,
			    k->privkeylen, k->encprivkey);
	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Walk down a Key blob extracting information                              */
/*                                                                          */
/****************************************************************************/
int TSS_KeyExtract(unsigned char *keybuff, keydata * k)
{
	int offset;
	int pubkeylen;

	/* fill in  keydata structure */
	offset = 0;
	memcpy(k->version, keybuff + offset, sizeof(k->version));
	offset += 4;
	k->keyusage = LOAD16(keybuff, offset);
	offset += TPM_U16_SIZE;
	k->keyflags = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	k->authdatausage = keybuff[offset];
	offset += 1;
	pubkeylen = TSS_PubKeyExtract(keybuff + offset, &(k->pub), 1);
	offset += pubkeylen;
	k->privkeylen = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	if (k->privkeylen > 0 && k->privkeylen <= 1024)
		memcpy(k->encprivkey, keybuff + offset, k->privkeylen);
	offset += k->privkeylen;
	return offset;
}

/****************************************************************************/
/*                                                                          */
/* Walk down a Public Key blob extracting information                       */
/*                                                                          */
/****************************************************************************/
int TSS_PubKeyExtract(unsigned char *keybuff, pubkeydata * k,
		      int pcrpresent)
{
	uint32_t parmsize;
	uint32_t pcrisize;

	int offset;

	offset = 0;
	k->algorithm = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	k->encscheme = LOAD16(keybuff, offset);
	offset += TPM_U16_SIZE;
	k->sigscheme = LOAD16(keybuff, offset);
	offset += TPM_U16_SIZE;
	parmsize = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	if (k->algorithm == 0x00000001 && parmsize > 0) {	/* RSA */
		k->keybitlen = LOAD32(keybuff, offset);
		offset += TPM_U32_SIZE;
		k->numprimes = LOAD32(keybuff, offset);
		offset += TPM_U32_SIZE;
		k->expsize = LOAD32(keybuff, offset);
		offset += TPM_U32_SIZE;
	} else {
		offset += parmsize;
	}
	if (k->expsize == 3) {
		k->exponent[0] = *(keybuff + offset + 0);
		k->exponent[1] = *(keybuff + offset + 1);
		k->exponent[2] = *(keybuff + offset + 2);
		offset += k->expsize;
	} else if (k->expsize != 0)
		offset += k->expsize;
	else {
		k->exponent[0] = 0x01;
		k->exponent[1] = 0x00;
		k->exponent[2] = 0x01;
		k->expsize = 3;
	}
	if (pcrpresent) {
		pcrisize = LOAD32(keybuff, offset);
		offset += TPM_U32_SIZE;
		if (pcrisize > 0 && pcrisize <= 256)
			memcpy(k->pcrinfo, keybuff + offset, pcrisize);
		offset += pcrisize;
		k->pcrinfolen = pcrisize;
	}
	k->keylength = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	if (k->keylength > 0 && k->keylength <= 256)
		memcpy(k->modulus, keybuff + offset, k->keylength);
	offset += k->keylength;
	return offset;
}

/****************************************************************************/
/*                                                                          */
/* Extract a Pubkey Blob from a Key Blob                                    */
/*                                                                          */
/****************************************************************************/
void TSS_Key2Pub(unsigned char *keybuff, unsigned char *pkey,
		 unsigned int *plen)
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
	len1 = TPM_U32_SIZE + TPM_U16_SIZE + TPM_U16_SIZE + TPM_U32_SIZE;
	memcpy(pkey + dstoff1, keybuff + srcoff1, len1);
	dstoff2 = dstoff1 + len1;
	srcoff2 = srcoff1 + len1;
	pointer = srcoff1 + TPM_U32_SIZE + TPM_U16_SIZE + TPM_U16_SIZE;
	parmsize = LOAD32(keybuff, pointer);
	len2 = parmsize;
	memcpy(pkey + dstoff2, keybuff + srcoff2, len2);
	pointer = pointer + TPM_U32_SIZE + parmsize;
	pcrisize = LOAD32(keybuff, pointer);
	pointer = pointer + TPM_U32_SIZE + pcrisize;
	pubksize = LOAD32(keybuff, pointer);
	dstoff3 = dstoff2 + len2;
	srcoff3 = pointer;
	len3 = pubksize + TPM_U32_SIZE;
	memcpy(pkey + dstoff3, keybuff + srcoff3, len3);
	*plen = len1 + len2 + len3;
}

/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Key Blob                                         */
/*                                                                          */
/****************************************************************************/
int TSS_KeySize(unsigned char *keybuff)
{
	int offset;
	int privkeylen;

	offset = 0 + 4 + TPM_U16_SIZE + TPM_U32_SIZE + 1;
	offset += TSS_PubKeySize(keybuff + offset, 1);
	privkeylen = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE + privkeylen;
	return offset;
}

/****************************************************************************/
/*                                                                          */
/* Calculate the size of a Public Key Blob                                  */
/*                                                                          */
/****************************************************************************/
int TSS_PubKeySize(unsigned char *keybuff, int pcrpresent)
{
	uint32_t parmsize;
	uint32_t pcrisize;
	uint32_t keylength;

	int offset;

	offset = 0 + TPM_U32_SIZE + TPM_U16_SIZE + TPM_U16_SIZE;
	parmsize = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	offset += parmsize;
	if (pcrpresent) {
		pcrisize = LOAD32(keybuff, offset);
		offset += TPM_U32_SIZE;
		offset += pcrisize;
	}
	keylength = LOAD32(keybuff, offset);
	offset += TPM_U32_SIZE;
	offset += keylength;
	return offset;
}

/****************************************************************************/
/*                                                                          */
/* Convert a TPM public key to an OpenSSL RSA public key                    */
/*                                                                          */
/****************************************************************************/
RSA *TSS_convpubkey(pubkeydata * k)
{
	RSA *rsa;
	BIGNUM *mod;
	BIGNUM *exp;

	/* create the necessary structures */
	rsa = RSA_new();
	mod = BN_new();
	exp = BN_new();
	if (rsa == NULL || mod == NULL || exp == NULL)
		return NULL;
	/* convert the raw public key values to BIGNUMS */
	BN_bin2bn(k->modulus, k->keylength, mod);
	BN_bin2bn(k->exponent, k->expsize, exp);
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
void TSS_pkeyprint(pubkeydata * key, unsigned char *fprint)
{
	TSS_sha1(key->modulus, key->keylength, fprint);
}

/****************************************************************************/
/*                                                                          */
/* Get the Fingerprint of a Key given a key blob                            */
/*                                                                          */
/****************************************************************************/
void TSS_keyprint(unsigned char *keybuff, unsigned char *fprint)
{
	keydata k;

	TSS_KeyExtract(keybuff, &k);
	TSS_pkeyprint(&(k.pub), fprint);
}

/****************************************************************************/
/*                                                                          */
/* Get the Fingerprint of a Key given a loaded key handle and authdata      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_lkeyprint(uint32_t keyhandle, unsigned char *keyauth,
		       unsigned char *fprint)
{
	uint32_t ret;
	unsigned char keyblob[TPM_MAX_BUFF_SIZE];
	unsigned int keyblen;
	pubkeydata k;

	ret = TPM_GetPubKey(keyhandle, keyauth, keyblob, &keyblen);
	if (ret != 0)
		return ret;
	TSS_PubKeyExtract(keyblob, &k, 0);
	TSS_pkeyprint(&k, fprint);
	return 0;
}
