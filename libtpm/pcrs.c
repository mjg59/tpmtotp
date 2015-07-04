/*
 * libtpm: PCR routines
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
#include <openssl/sha.h>
#include <oiaposap.h>
#include <hmac.h>
#include <pcrs.h>

static uint32_t TSS_GenPCRSel(uint32_t pcrmap, unsigned char *pcrselect,
			      unsigned int *len);

/****************************************************************************/
/*                                                                          */
/* Quote the specified PCR registers                                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to sign the results              */
/* pcrmap    is a 32 bit integer containing a bit map of the PCR register   */
/*           numbers to be used when sealing. e.g 0x0000001 specifies       */
/*           PCR 0. 0x00000003 specifies PCR's 0 and 1, etc.                */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it will be assumed that no password is required       */
/* data      is a pointer to the data to be sealed  (20 bytes)              */
/* pcrcompos is a pointer to an area to receive a pcrcomposite structure    */
/* blob      is a pointer to an area to receive the signed data             */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the signed data                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Quote(uint32_t keyhandle,
		   uint32_t pcrmap,
		   unsigned char *keyauth,
		   unsigned char *data,
		   unsigned char *pcrcompos,
		   unsigned char *blob, unsigned int *bloblen)
{
	unsigned char quote_fmt[] = "00 C2 T l l % % l % o %";
	unsigned char quote_fmt_noauth[] = "00 C1 T l l % %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	osapsess sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t pcrselsize;
	uint32_t valuesize;
	uint32_t sigsize;
	uint32_t storedsize;
	uint32_t keyhndl;
	uint16_t keytype;
	struct pcrsel {
		uint16_t selsize;
		unsigned char select[TPM_PCR_MASK_SIZE];
	} myinfo;

	/* check input arguments */
	if (pcrcompos == NULL || data == NULL || blob == NULL)
		return ERR_NULL_ARG;
	keytype = 0x0001;
	ret =
	    TSS_GenPCRSel(pcrmap, (unsigned char *) &myinfo, &pcrselsize);
	if (ret != 0)
		return ret;
	if (keyauth != NULL) {	/* authdata required */
		/* Open OSAP Session */
		ret = TSS_OSAPopen(&sess, keyauth, keytype, keyhandle);
		if (ret != 0)
			return ret;
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x16);
		keyhndl = htonl(keyhandle);
		c = 0;
		/* calculate authorization HMAC value */
		ret =
		    TSS_authhmac(pubauth, sess.ssecret, TPM_HASH_SIZE,
				 sess.enonce, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_HASH_SIZE, data,
				 sizeof(struct pcrsel), &myinfo, 0, 0);
		if (ret != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(quote_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    TPM_HASH_SIZE, data,
				    sizeof(struct pcrsel), &myinfo,
				    sess.handle,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "Quote");
		if (ret != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* calculate the size of the returned Blob */
		pcrselsize = LOAD16(tpmdata, TPM_DATA_OFFSET);
		valuesize =
		    LOAD32(tpmdata,
			   TPM_DATA_OFFSET + TPM_U16_SIZE + pcrselsize);
		sigsize =
		    LOAD32(tpmdata,
			   TPM_DATA_OFFSET + TPM_U16_SIZE + pcrselsize +
			   TPM_U32_SIZE + valuesize);
		storedsize =
		    TPM_U16_SIZE + pcrselsize + TPM_U32_SIZE + valuesize +
		    TPM_U32_SIZE + sigsize;
		/* check the HMAC in the response */
		ret =
		    TSS_checkhmac1(tpmdata, ordinal, nonceodd,
				   sess.ssecret, TPM_HASH_SIZE, storedsize,
				   TPM_DATA_OFFSET, 0, 0);
		if (ret != 0) {
			TSS_OSAPclose(&sess);
			return ret;
		}
		/* copy the returned PCR composite to caller */
		memcpy(pcrcompos, tpmdata + TPM_DATA_OFFSET,
		       TPM_U16_SIZE + pcrselsize + TPM_U32_SIZE +
		       valuesize);
		/* copy the returned blob to caller */
		memcpy(blob,
		       tpmdata + TPM_DATA_OFFSET + TPM_U16_SIZE +
		       pcrselsize + TPM_U32_SIZE + valuesize +
		       TPM_U32_SIZE, sigsize);
		*bloblen = sigsize;
		TSS_OSAPclose(&sess);
	} else {		/* no authdata required */

		/* Network byte order data to variables for hmac calculation */
		ordinal = htonl(0x16);
		keyhndl = htonl(keyhandle);
		/* build the request buffer */
		ret = TSS_buildbuff(quote_fmt_noauth, tpmdata,
				    ordinal,
				    keyhndl,
				    TPM_HASH_SIZE, data,
				    sizeof(struct pcrsel), &myinfo);
		if ((ret & ERR_MASK) != 0)
			return ret;
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "Quote");
		if (ret != 0)
			return ret;
		/* calculate the size of the returned Blob */
		pcrselsize = LOAD16(tpmdata, TPM_DATA_OFFSET);
		valuesize =
		    LOAD32(tpmdata,
			   TPM_DATA_OFFSET + TPM_U16_SIZE + pcrselsize);
		sigsize =
		    LOAD32(tpmdata,
			   TPM_DATA_OFFSET + TPM_U16_SIZE + pcrselsize +
			   TPM_U32_SIZE + valuesize);
		storedsize =
		    TPM_U16_SIZE + pcrselsize + TPM_U32_SIZE + valuesize +
		    TPM_U32_SIZE + sigsize;
		/* copy the returned PCR composite to caller */
		memcpy(pcrcompos, tpmdata + TPM_DATA_OFFSET,
		       TPM_U16_SIZE + pcrselsize + TPM_U32_SIZE +
		       valuesize);
		/* copy the returned blob to caller */
		memcpy(blob,
		       tpmdata + TPM_DATA_OFFSET + TPM_U16_SIZE +
		       pcrselsize + TPM_U32_SIZE + valuesize +
		       TPM_U32_SIZE, sigsize);
		*bloblen = sigsize;
	}
	return 0;
}


/****************************************************************************/
/*                                                                          */
/*  Read PCR value                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue)
{
	unsigned char pcrread_fmt[] = "00 c1 T 00 00 00 15 L";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];

	if (pcrvalue == NULL)
		return ERR_NULL_ARG;
	ret = TSS_buildbuff(pcrread_fmt, tpmdata, pcrindex);
	if ((ret & ERR_MASK) != 0)
		return ret;
	ret = TPM_Transmit(tpmdata, "PCRRead");
	if (ret != 0)
		return ret;
	memcpy(pcrvalue, tpmdata + TPM_DATA_OFFSET, TPM_HASH_SIZE);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/*  Create PCR_INFO structure using current PCR values                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_GenPCRInfo(uint32_t pcrmap, unsigned char *pcrinfo,
			unsigned int *len)
{
	struct pcrinfo {
		uint16_t selsize;
		unsigned char select[TPM_PCR_MASK_SIZE];
		unsigned char relhash[TPM_HASH_SIZE];
		unsigned char crthash[TPM_HASH_SIZE];
	} myinfo;
	int i;
	int j;
	uint32_t work;
	unsigned char *valarray;
	uint32_t numregs;
	uint32_t ret;
	uint32_t valsize;
	SHA_CTX sha;


	/* check arguments */
	if (pcrinfo == NULL || len == NULL)
		return ERR_NULL_ARG;
	/* build pcr selection array */
	work = pcrmap;
	memset(myinfo.select, 0, TPM_PCR_MASK_SIZE);
	for (i = 0; i < TPM_PCR_MASK_SIZE; ++i) {
		myinfo.select[i] = work & 0x000000FF;
		work = work >> 8;
	}
	/* calculate number of PCR registers requested */
	numregs = 0;
	work = pcrmap;
	for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i) {
		if (work & 1)
			++numregs;
		work = work >> 1;
	}
	if (numregs == 0) {
		*len = 0;
		return 0;
	}
	/* create the array of PCR values */
	valarray = (unsigned char *) malloc(TPM_HASH_SIZE * numregs);
	/* read the PCR values into the value array */
	work = pcrmap;
	j = 0;
	for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i, work = work >> 1) {
		if ((work & 1) == 0)
			continue;
		ret = TPM_PcrRead(i, &(valarray[(j * TPM_HASH_SIZE)]));
		if (ret)
			return ret;
		++j;
	}
	myinfo.selsize = ntohs(TPM_PCR_MASK_SIZE);
	valsize = ntohl(numregs * TPM_HASH_SIZE);
	/* calculate composite hash */
	SHA1_Init(&sha);
	SHA1_Update(&sha, &myinfo.selsize, TPM_U16_SIZE);
	SHA1_Update(&sha, &myinfo.select, TPM_PCR_MASK_SIZE);
	SHA1_Update(&sha, &valsize, TPM_U32_SIZE);
	for (i = 0; i < numregs; ++i) {
		SHA1_Update(&sha, &(valarray[(i * TPM_HASH_SIZE)]),
			    TPM_HASH_SIZE);
	}
	SHA1_Final(myinfo.relhash, &sha);
	memcpy(myinfo.crthash, myinfo.relhash, TPM_HASH_SIZE);
	memcpy(pcrinfo, &myinfo, sizeof(struct pcrinfo));
	*len = sizeof(struct pcrinfo);
	return 0;
}


/****************************************************************************/
/*                                                                          */
/*  Create PCR_Selection structure using a 32 bit mask                      */
/*                                                                          */
/****************************************************************************/
static uint32_t TSS_GenPCRSel(uint32_t pcrmap, unsigned char *pcrselect,
			      unsigned int *len)
{
	struct pcrsel {
		uint16_t selsize;
		unsigned char select[TPM_PCR_MASK_SIZE];
	} myinfo;

	int i;
	uint32_t work;

	/* build pcr selection array */
	work = pcrmap;
	memset(myinfo.select, 0, TPM_PCR_MASK_SIZE);
	myinfo.selsize = ntohs(TPM_PCR_MASK_SIZE);
	for (i = 0; i < TPM_PCR_MASK_SIZE; ++i) {
		myinfo.select[i] = work & 0x000000FF;
		work = work >> 8;
	}
	memcpy(pcrselect, &myinfo, sizeof(struct pcrsel));
	*len = sizeof(struct pcrsel);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/*  Extend PCR value                                                        */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Extend(uint32_t pcrindex, unsigned char *pcrvalue)
{
        char extend_fmt[] = "00 c1 T 00 00 00 14 L %";
        uint32_t ret;
        unsigned char tpmdata[TPM_MAX_BUFF_SIZE]; /* request/response buffer */

        if (pcrvalue == NULL)
                return ERR_NULL_ARG;
        ret = TSS_buildbuff(extend_fmt, tpmdata, pcrindex, 20, pcrvalue);
        if ((ret & ERR_MASK) != 0)
                return ret;
        ret = TPM_Transmit(tpmdata, "Extend");
        if (ret != 0)
                return ret;
        return 0;
}
