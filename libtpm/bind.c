/*
 * libtpm: bind/unbind routines
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
#include <tpmkeys.h>
#include <oiaposap.h>
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
		    unsigned char *data, unsigned int datalen,
		    unsigned char *blob, unsigned int *bloblen)
{
	unsigned char unbind_fmt[] = "00 C2 T l l @ l % o %";
	unsigned char unbind_fmt_noauth[] = "00 C1 T l l @";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t datsize;
	uint32_t keyhndl;
	uint16_t keytype;
	uint32_t infosize;

	/* check input arguments */
	if (data == NULL || blob == NULL)
		return ERR_NULL_ARG;
	if (keyhandle == 0x40000000)
		keytype = 0x0004;
	else
		keytype = 0x0001;
	if (keyauth != NULL) {	/* key needs authorization */
		/* Open OSAP Session */
		ret = TSS_OSAPopen(&sess, keyauth, keytype, keyhandle);
		if (ret != 0)
			return ret;
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x1E);
		datsize = htonl(datalen);
		keyhndl = htonl(keyhandle);
		c = 0;
		/* calculate authorization HMAC value */
		ret =
		    TSS_authhmac(pubauth, sess.ssecret, TPM_HASH_SIZE,
				 sess.enonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_U32_SIZE, &datsize, datalen,
				 data, 0, 0);
		if (ret != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(unbind_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    datalen, data,
				    sess.handle,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "UnBind");
		if (ret != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* calculate the size of the returned Blob */
		infosize = LOAD32(tpmdata, TPM_DATA_OFFSET);
		/* check the HMAC in the response */
		ret =
		    TSS_checkhmac1(tpmdata, ordinal, nonceodd,
				   sess.ssecret, TPM_HASH_SIZE,
				   TPM_U32_SIZE, TPM_DATA_OFFSET, infosize,
				   TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		if (ret != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* copy the returned blob to caller */
		memcpy(blob, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE,
		       infosize);
		*bloblen = infosize;
		TSS_OSAPclose(&sess);
	} else {		/* key needs NO authorization */

		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x1E);
		datsize = htonl(datalen);
		keyhndl = htonl(keyhandle);
		/* build the request buffer */
		ret = TSS_buildbuff(unbind_fmt_noauth, tpmdata,
				    ordinal, keyhndl, datalen, data);
		if ((ret & ERR_MASK) != 0)
			return ret;
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "UnBind");
		if (ret != 0)
			return ret;
		/* calculate the size of the returned Blob */
		infosize = LOAD32(tpmdata, TPM_DATA_OFFSET);
		/* copy the returned blob to caller */
		memcpy(blob, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE,
		       infosize);
		*bloblen = infosize;
	}
	return 0;
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
uint32_t TSS_Bind(RSA * key,
		  unsigned char *data, unsigned int datalen,
		  unsigned char *blob, unsigned int *bloblen)
{
	uint32_t ret;
	unsigned char blob2[256];
	/* check input arguments */
	if (key == NULL || data == NULL || blob == NULL)
		return ERR_NULL_ARG;
	if (datalen > 256)
		return ERR_BAD_ARG;
	ret =
	    RSA_padding_add_PKCS1_OAEP(blob2, 256, data, datalen, "TCPA",
				       4);
	if (ret != 1)
		return ERR_CRYPT_ERR;
	ret = RSA_public_encrypt(256, blob2, blob, key, RSA_NO_PADDING);
	if (ret == -1)
		return ERR_CRYPT_ERR;
	*bloblen = ret;
	return 0;
}
