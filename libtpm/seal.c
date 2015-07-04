/*
 * libtpm: seal/unseal routines
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
#include <pcrs.h>

#define MAXPCRINFOLEN ( (TPM_HASH_SIZE * 2) + TPM_U16_SIZE + TPM_PCR_MASK_SIZE )

/****************************************************************************/
/*                                                                          */
/* Seal a data object with caller Specified PCR infro                       */
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
		  unsigned char *data, unsigned int datalen,
		  unsigned char *blob, unsigned int *bloblen)
{
	unsigned char seal_fmt[] = "00 C2 T l l % @ @ l % o %";
	uint32_t ret;
	int i;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char xorwork[TPM_HASH_SIZE * 2];
	unsigned char xorhash[TPM_HASH_SIZE];
	unsigned char dummyauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t pcrsize;
	uint32_t datsize;
	uint32_t keyhndl;
	uint16_t keytype;
	unsigned char *passptr1;
	unsigned char *passptr2;
	int sealinfosize;
	int encdatasize;
	int storedsize;

	memset(dummyauth, 0, sizeof dummyauth);
	/* check input arguments */
	if (data == NULL || blob == NULL)
		return ERR_NULL_ARG;
	if (pcrinfosize != 0 && pcrinfo == NULL)
		return ERR_NULL_ARG;
	if (keyhandle == 0x40000000)
		keytype = 0x0004;
	else
		keytype = 0x0001;
	if (keyauth == NULL)
		passptr1 = dummyauth;
	else
		passptr1 = keyauth;
	if (dataauth == NULL)
		passptr2 = dummyauth;
	else
		passptr2 = dataauth;
	/* Open OSAP Session */
	ret = TSS_OSAPopen(&sess, passptr1, keytype, keyhandle);
	if (ret != 0)
		return ret;
	/* calculate encrypted authorization value */
	memcpy(xorwork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorwork + TPM_HASH_SIZE, sess.enonce, TPM_HASH_SIZE);
	TSS_sha1(xorwork, TPM_HASH_SIZE * 2, xorhash);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x17);
	datsize = htonl(datalen);
	keyhndl = htonl(keyhandle);
	pcrsize = htonl(pcrinfosize);
	c = 0;
	/* encrypt data authorization key */
	for (i = 0; i < TPM_HASH_SIZE; ++i)
		encauth[i] = xorhash[i] ^ passptr2[i];
	/* calculate authorization HMAC value */
	if (pcrinfosize == 0) {
		/* no pcr info specified */
		ret =
		    TSS_authhmac(pubauth, sess.ssecret, TPM_HASH_SIZE,
				 sess.enonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_HASH_SIZE, encauth,
				 TPM_U32_SIZE, &pcrsize, TPM_U32_SIZE,
				 &datsize, datalen, data, 0, 0);
	} else {
		/* pcr info specified */
		ret =
		    TSS_authhmac(pubauth, sess.ssecret, TPM_HASH_SIZE,
				 sess.enonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_HASH_SIZE, encauth,
				 TPM_U32_SIZE, &pcrsize, pcrinfosize,
				 pcrinfo, TPM_U32_SIZE, &datsize, datalen,
				 data, 0, 0);
	}
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(seal_fmt, tpmdata,
			    ordinal,
			    keyhndl,
			    TPM_HASH_SIZE, encauth,
			    pcrinfosize, pcrinfo,
			    datalen, data,
			    sess.handle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "Seal");
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* calculate the size of the returned Blob */
	sealinfosize = LOAD32(tpmdata, TPM_DATA_OFFSET + TPM_U32_SIZE);
	encdatasize =
	    LOAD32(tpmdata,
		   TPM_DATA_OFFSET + TPM_U32_SIZE + TPM_U32_SIZE +
		   sealinfosize);
	storedsize =
	    TPM_U32_SIZE + TPM_U32_SIZE + sealinfosize + TPM_U32_SIZE +
	    encdatasize;
	/* check the HMAC in the response */
	ret =
	    TSS_checkhmac1(tpmdata, ordinal, nonceodd, sess.ssecret,
			   TPM_HASH_SIZE, storedsize, TPM_DATA_OFFSET, 0,
			   0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* copy the returned blob to caller */
	memcpy(blob, tpmdata + TPM_DATA_OFFSET, storedsize);
	*bloblen = storedsize;
	TSS_OSAPclose(&sess);
	return 0;
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
			 unsigned char *data, unsigned int datalen,
			 unsigned char *blob, unsigned int *bloblen)
{
	uint32_t ret;
	unsigned char pcrinfo[MAXPCRINFOLEN];
	uint32_t pcrlen;

	ret = TSS_GenPCRInfo(pcrmap, pcrinfo, &pcrlen);
	if (ret != 0)
		return ret;
	return TPM_Seal(keyhandle,
			pcrinfo, pcrlen,
			keyauth, dataauth, data, datalen, blob, bloblen);
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
		    unsigned char *blob, unsigned int bloblen,
		    unsigned char *rawdata, unsigned int *datalen)
{
	unsigned char unseal_fmt[] = "00 C3 T l l % l % o % l % o %";
	unsigned char unseal_fmt_noauth[] = "00 C2 T l l % l % o %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char enonce1[TPM_NONCE_SIZE];
	unsigned char enonce2[TPM_NONCE_SIZE];
	unsigned char dummyauth[TPM_NONCE_SIZE];
	unsigned char *passptr2;
	unsigned char c;
	uint32_t ordinal;
	uint32_t keyhndl;
	uint32_t authhandle1;
	uint32_t authhandle2;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];

	memset(dummyauth, 0, sizeof dummyauth);
	/* check input arguments */
	if (rawdata == NULL || blob == NULL)
		return ERR_NULL_ARG;
	if (dataauth == NULL)
		passptr2 = dummyauth;
	else
		passptr2 = dataauth;
	if (keyauth != NULL) {	/* key password specified */
		/* open TWO OIAP sessions, Key and Data */
		ret = TSS_OIAPopen(&authhandle1, enonce1);
		if (ret != 0)
			return ret;
		ret = TSS_OIAPopen(&authhandle2, enonce2);
		if (ret != 0)
			return ret;
		/* data to Network byte order variables for HMAC calculation */
		ordinal = htonl(0x18);
		keyhndl = htonl(keyhandle);
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		c = 0;
		/* calculate KEY authorization HMAC value */
		ret =
		    TSS_authhmac(authdata1, keyauth, TPM_HASH_SIZE,
				 enonce1, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, bloblen, blob, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* calculate DATA authorization HMAC value */
		ret =
		    TSS_authhmac(authdata2, passptr2, TPM_NONCE_SIZE,
				 enonce2, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, bloblen, blob, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(unseal_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    bloblen, blob,
				    authhandle1,
				    TPM_NONCE_SIZE, nonceodd,
				    c,
				    TPM_HASH_SIZE, authdata1,
				    authhandle2,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, authdata2);

		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "Unseal");
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		*datalen = LOAD32(tpmdata, TPM_DATA_OFFSET);
		/* check HMAC in response */
		ret = TSS_checkhmac2(tpmdata, ordinal, nonceodd,
				     keyauth, TPM_HASH_SIZE,
				     passptr2, TPM_HASH_SIZE,
				     TPM_U32_SIZE, TPM_DATA_OFFSET,
				     *datalen,
				     TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		TSS_OIAPclose(authhandle1);
		TSS_OIAPclose(authhandle2);
		if (ret != 0)
			return ret;
	} else {		/* no key password */

		/* open ONE OIAP session, for the Data */
		ret = TSS_OIAPopen(&authhandle2, enonce2);
		if (ret != 0)
			return ret;
		/* data to Network byte order variables for HMAC calculation */
		ordinal = htonl(0x18);
		keyhndl = htonl(keyhandle);
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		c = 0;
		/* calculate DATA authorization HMAC value */
		ret =
		    TSS_authhmac(authdata2, passptr2, TPM_NONCE_SIZE,
				 enonce2, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, bloblen, blob, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(unseal_fmt_noauth, tpmdata,
				    ordinal,
				    keyhndl,
				    bloblen, blob,
				    authhandle2,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, authdata2);

		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "Unseal");
		if (ret != 0) {
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		*datalen = LOAD32(tpmdata, TPM_DATA_OFFSET);
		/* check HMAC in response */
		ret = TSS_checkhmac1(tpmdata, ordinal, nonceodd,
				     passptr2, TPM_HASH_SIZE,
				     TPM_U32_SIZE, TPM_DATA_OFFSET,
				     *datalen,
				     TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		TSS_OIAPclose(authhandle2);
		if (ret != 0)
			return ret;
	}
	/* copy decrypted data back to caller */
	memcpy(rawdata, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE,
	       *datalen);
	return 0;
}
