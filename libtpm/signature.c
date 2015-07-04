/*
 * libtpm: sign routines
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
		  unsigned char *data, int datalen,
		  unsigned char *sig, unsigned int *siglen)
{
	unsigned char sign_fmt[] = "00 c2 T l l @ l % o %";
	unsigned char sign_fmt_noauth[] = "00 c1 T l l @";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t keyhndl;
	uint32_t authhandle;
	uint32_t datasize;
	uint32_t sigsize;

	/* check input arguments */
	if (data == NULL || sig == NULL)
		return ERR_NULL_ARG;
	if (keyauth != NULL) {	/* key requires authorization */
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Open OIAP Session */
		ret = TSS_OIAPopen(&authhandle, evennonce);
		if (ret != 0)
			return ret;
		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x3C);
		keyhndl = htonl(keyhandle);
		datasize = htonl(datalen);
		c = 0;
		/* calculate authorization HMAC value */
		ret =
		    TSS_authhmac(pubauth, keyauth, TPM_HASH_SIZE,
				 evennonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_U32_SIZE, &datasize,
				 datalen, data, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(sign_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    datalen, data,
				    authhandle,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "Sign");
		if (ret != 0) {
			TSS_OIAPclose(authhandle);
			return ret;
		}
		TSS_OIAPclose(authhandle);
		sigsize = LOAD32(tpmdata, TPM_DATA_OFFSET);
		/* check the HMAC in the response */
		ret =
		    TSS_checkhmac1(tpmdata, ordinal, nonceodd, keyauth,
				   TPM_HASH_SIZE, TPM_U32_SIZE,
				   TPM_DATA_OFFSET, sigsize,
				   TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		if (ret != 0)
			return ret;
		memcpy(sig, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE,
		       sigsize);
		*siglen = sigsize;
	} else {		/* key requires NO authorization */

		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x3C);
		keyhndl = htonl(keyhandle);
		datasize = htonl(datalen);
		/* build the request buffer */
		ret = TSS_buildbuff(sign_fmt_noauth, tpmdata,
				    ordinal, keyhndl, datalen, data);
		if ((ret & ERR_MASK) != 0)
			return ret;
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "Sign");
		if (ret != 0)
			return ret;
		sigsize = LOAD32(tpmdata, TPM_DATA_OFFSET);
		memcpy(sig, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE,
		       sigsize);
		*siglen = sigsize;
	}
	return 0;
}
