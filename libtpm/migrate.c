/*
 * libtpm: key migration routines
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

/****************************************************************************/
/*                                                                          */
/* Authorize a Migration Key                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is a pointer to the Owner password (20 bytes)                  */
/* migtype   is an integer containing 1 for normal migration and 2 for      */
/*           rewrap migration                                               */
/* keyblob   is a pointer to an area contining the migration public         */
/*           encrypted key blob                                             */
/* keyblen   is an integer containing the length of the migration           */
/*           public key blob                                                */
/* migblob   is a pointer to an area which will receive the migration       */
/*           key authorization blob                                         */
/* migblen   is a pointer to an integer which will receive the migration    */
/*           key authorization blob length                                  */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_AuthorizeMigrationKey(unsigned char *ownpass,
				   int migtype,
				   unsigned char *keyblob,
				   unsigned int keyblen,
				   unsigned char *migblob,
				   unsigned int *migblen)
{
	unsigned char auth_mig_fmt[] = "00 c2 T l s % l % o %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint16_t migscheme;
	uint32_t authhandle;
	int size;

	/* check input arguments */
	if (keyblob == NULL || migblob == NULL || migblen == NULL)
		return ERR_NULL_ARG;
	if (migtype != 1 && migtype != 2)
		return ERR_BAD_ARG;
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* Open OIAP Session */
	ret = TSS_OIAPopen(&authhandle, evennonce);
	if (ret != 0)
		return ret;
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x2B);
	migscheme = htons(migtype);
	c = 0;
	/* calculate authorization HMAC value */
	ret =
	    TSS_authhmac(pubauth, ownpass, TPM_HASH_SIZE, evennonce,
			 nonceodd, c, TPM_U32_SIZE, &ordinal, TPM_U16_SIZE,
			 &migscheme, keyblen, keyblob, 0, 0);
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(auth_mig_fmt, tpmdata,
			    ordinal,
			    migscheme,
			    keyblen, keyblob,
			    authhandle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "AuthMigrationKey");
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	TSS_OIAPclose(authhandle);
	size = TSS_PubKeySize(tpmdata + TPM_DATA_OFFSET, 0);
	size += TPM_U16_SIZE + TPM_HASH_SIZE;
	ret =
	    TSS_checkhmac1(tpmdata, ordinal, nonceodd, ownpass,
			   TPM_HASH_SIZE, size, TPM_DATA_OFFSET, 0, 0);
	if (ret != 0)
		return ret;
	memcpy(migblob, tpmdata + TPM_DATA_OFFSET, size);
	*migblen = size;
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
/* migblob   is a pointer to an area to containig the migration key         */
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
uint32_t TPM_CreateMigrationBlob(unsigned int keyhandle,
				 unsigned char *keyauth,
				 unsigned char *migauth,
				 int migtype,
				 unsigned char *migblob,
				 unsigned int migblen,
				 unsigned char *keyblob,
				 unsigned int keyblen,
				 unsigned char *rndblob,
				 unsigned int *rndblen,
				 unsigned char *outblob,
				 unsigned int *outblen)
{
	unsigned char create_mig_fmt[] =
	    "00 c3 T l l s % @ l % o % l % o %";
	unsigned char create_mig_fmt_noauth[] =
	    "00 c2 T l l s % @ l % o %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char enonce1[TPM_NONCE_SIZE];
	unsigned char enonce2[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t keyhndl;
	uint32_t datsize;
	uint16_t migscheme;
	uint32_t authhandle1;
	uint32_t authhandle2;
	unsigned char authdata1[TPM_HASH_SIZE];
	unsigned char authdata2[TPM_HASH_SIZE];
	uint32_t size1;
	uint32_t size2;
	keydata k;

	/* check input arguments */
	if (migauth == NULL || migblob == NULL || keyblob == NULL)
		return ERR_NULL_ARG;
	if (rndblob == NULL || rndblen == NULL || outblob == NULL
	    || outblen == NULL)
		return ERR_NULL_ARG;
	if (migtype != 1 && migtype != 2)
		return ERR_BAD_ARG;
	TSS_KeyExtract(keyblob, &k);
	/* move data to Network byte order variables for HMAC calculation */
	ordinal = htonl(0x28);
	keyhndl = htonl(keyhandle);
	migscheme = htons(migtype);
	datsize = htonl(k.privkeylen);
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	c = 0;
	if (keyauth != NULL) {	/* parent key password is required */
		/* open TWO OIAP sessions: Parent and Migrating Key */
		ret = TSS_OIAPopen(&authhandle1, enonce1);
		if (ret != 0)
			return ret;
		ret = TSS_OIAPopen(&authhandle2, enonce2);
		if (ret != 0)
			return ret;
		/* calculate Parent KEY authorization HMAC value */
		ret =
		    TSS_authhmac(authdata1, keyauth, TPM_HASH_SIZE,
				 enonce1, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_U16_SIZE, &migscheme,
				 migblen, migblob, TPM_U32_SIZE, &datsize,
				 k.privkeylen, k.encprivkey, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* calculate Migration authorization HMAC value */
		ret =
		    TSS_authhmac(authdata2, migauth, TPM_HASH_SIZE,
				 enonce2, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_U16_SIZE, &migscheme,
				 migblen, migblob, TPM_U32_SIZE, &datsize,
				 k.privkeylen, k.encprivkey, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(create_mig_fmt, tpmdata,
				    ordinal,
				    keyhndl,
				    migscheme,
				    migblen, migblob,
				    k.privkeylen, k.encprivkey,
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
		ret = TPM_Transmit(tpmdata, "CreateMigrationBlob");
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			TSS_OIAPclose(authhandle2);
			return ret;
		}
		/* validate HMAC in response */
		size1 = LOAD32(tpmdata, TPM_DATA_OFFSET);
		size2 =
		    LOAD32(tpmdata,
			   TPM_DATA_OFFSET + TPM_U32_SIZE + size1);
		if (size1 != 0) {
			ret = TSS_checkhmac2(tpmdata, ordinal, nonceodd,
					     keyauth, TPM_HASH_SIZE,
					     migauth, TPM_HASH_SIZE,
					     TPM_U32_SIZE, TPM_DATA_OFFSET,
					     size1,
					     TPM_DATA_OFFSET +
					     TPM_U32_SIZE, TPM_U32_SIZE,
					     TPM_DATA_OFFSET +
					     TPM_U32_SIZE + size1, size2,
					     TPM_DATA_OFFSET +
					     TPM_U32_SIZE + size1 +
					     TPM_U32_SIZE, 0, 0);
		} else {
			ret = TSS_checkhmac2(tpmdata, ordinal, nonceodd,
					     keyauth, TPM_HASH_SIZE,
					     migauth, TPM_HASH_SIZE,
					     TPM_U32_SIZE, TPM_DATA_OFFSET,
					     TPM_U32_SIZE,
					     TPM_DATA_OFFSET +
					     TPM_U32_SIZE, size2,
					     TPM_DATA_OFFSET +
					     TPM_U32_SIZE + TPM_U32_SIZE,
					     0, 0);
		}
		TSS_OIAPclose(authhandle1);
		TSS_OIAPclose(authhandle2);
		if (ret != 0)
			return ret;
	} else {		/* no parent key password required */

		/* open OIAP session for the Migrating Key */
		ret = TSS_OIAPopen(&authhandle1, enonce1);
		if (ret != 0)
			return ret;
		/* calculate Migration authorization HMAC value */
		ret =
		    TSS_authhmac(authdata1, migauth, TPM_HASH_SIZE,
				 enonce1, nonceodd, c, TPM_U32_SIZE,
				 &ordinal, TPM_U16_SIZE, &migscheme,
				 migblen, migblob, TPM_U32_SIZE, &datsize,
				 k.privkeylen, k.encprivkey, 0, 0);
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff(create_mig_fmt_noauth, tpmdata,
				    ordinal,
				    keyhndl,
				    migscheme,
				    migblen, migblob,
				    k.privkeylen, k.encprivkey,
				    authhandle1,
				    TPM_NONCE_SIZE, nonceodd,
				    c, TPM_HASH_SIZE, authdata1);

		if ((ret & ERR_MASK) != 0) {
			TSS_OIAPclose(authhandle1);
			return ret;
		}
		/* transmit buffer to the TPM device and read the reply */
		ret = TPM_Transmit(tpmdata, "CreateMigrationBlob");
		if (ret != 0) {
			TSS_OIAPclose(authhandle1);
			return ret;
		}
		/* check HMAC in response */
		size1 = LOAD32(tpmdata, TPM_DATA_OFFSET);
		size2 =
		    LOAD32(tpmdata,
			   TPM_DATA_OFFSET + TPM_U32_SIZE + size1);
		if (size1 != 0) {
			ret =
			    TSS_checkhmac1(tpmdata, ordinal, nonceodd,
					   migauth, TPM_HASH_SIZE,
					   TPM_U32_SIZE, TPM_DATA_OFFSET,
					   size1,
					   TPM_DATA_OFFSET + TPM_U32_SIZE,
					   TPM_U32_SIZE,
					   TPM_DATA_OFFSET + TPM_U32_SIZE +
					   size1, size2,
					   TPM_DATA_OFFSET + TPM_U32_SIZE +
					   size1 + TPM_U32_SIZE, 0, 0);
		} else {
			ret =
			    TSS_checkhmac1(tpmdata, ordinal, nonceodd,
					   migauth, TPM_HASH_SIZE,
					   TPM_U32_SIZE, TPM_DATA_OFFSET,
					   TPM_U32_SIZE,
					   TPM_DATA_OFFSET + TPM_U32_SIZE,
					   size2,
					   TPM_DATA_OFFSET + TPM_U32_SIZE +
					   TPM_U32_SIZE, 0, 0);
		}
		TSS_OIAPclose(authhandle1);
		if (ret != 0)
			return ret;
	}
	memcpy(rndblob, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE, size1);
	memcpy(outblob,
	       tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE + size1 +
	       TPM_U32_SIZE, size2);
	*rndblen = size1;
	*outblen = size2;
	return 0;
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
/* rndblob   is a pointer to an area contining the random XOR data          */
/* rndblen   is an integer containing the length of the random XOR data     */
/* keyblob   is a pointer to an area contining the migration public         */
/*           encrypted key blob                                             */
/* keyblen   is an integer containing the length of the migration           */
/*           public key blob                                                */
/* encblob   is a pointer to an area which will receive the migrated        */
/*           key re-encrypted private key blob                              */
/* endblen   is a pointer to an integer which will receive size of          */
/*           the migrated key re-encrypted private key blob                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_ConvertMigrationBlob(unsigned int keyhandle,
				  unsigned char *keyauth,
				  unsigned char *rndblob,
				  unsigned int rndblen,
				  unsigned char *keyblob,
				  unsigned int keyblen,
				  unsigned char *encblob,
				  unsigned int *encblen)
{
	unsigned char convert_mig_fmt[] = "00 c2 T l l @ @ l % o %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char evennonce[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char c;
	uint32_t ordinal;
	uint32_t authhandle;
	uint32_t keyhndl;
	uint32_t rndsize;
	uint32_t datsize;
	int size;

	/* check input arguments */
	if (keyauth == NULL || rndblob == NULL || keyblob == NULL
	    || encblob == NULL || encblen == NULL)
		return ERR_NULL_ARG;
	/* generate odd nonce */
	TSS_gennonce(nonceodd);
	/* Open OIAP Session */
	ret = TSS_OIAPopen(&authhandle, evennonce);
	if (ret != 0)
		return ret;
	/* move Network byte order data to variables for hmac calculation */
	ordinal = htonl(0x2A);
	keyhndl = htonl(keyhandle);
	rndsize = htonl(rndblen);
	datsize = htonl(keyblen);
	c = 0;
	/* calculate authorization HMAC value */
	ret =
	    TSS_authhmac(pubauth, keyauth, TPM_HASH_SIZE, evennonce,
			 nonceodd, c, TPM_U32_SIZE, &ordinal, TPM_U32_SIZE,
			 &datsize, keyblen, keyblob, TPM_U32_SIZE,
			 &rndsize, rndblen, rndblob, 0, 0);
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff(convert_mig_fmt, tpmdata,
			    ordinal,
			    keyhndl,
			    keyblen, keyblob,
			    rndblen, rndblob,
			    authhandle,
			    TPM_NONCE_SIZE, nonceodd,
			    c, TPM_HASH_SIZE, pubauth);
	if ((ret & ERR_MASK) != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "ConvertMigrationBlob");
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	TSS_OIAPclose(authhandle);
	size = LOAD32(tpmdata, TPM_DATA_OFFSET);
	ret =
	    TSS_checkhmac1(tpmdata, ordinal, nonceodd, keyauth,
			   TPM_HASH_SIZE, TPM_U32_SIZE, TPM_DATA_OFFSET,
			   size, TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
	if (ret != 0)
		return ret;
	memcpy(encblob, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE, size);
	*encblen = size;
	return 0;
}
