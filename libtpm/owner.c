/*
 * libtpm: takeownership routines
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
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define TPM_SRK_PARAM_BUFF_SIZE 256
#define RSA_MODULUS_BYTE_SIZE 256
#define RSA_MODULUS_BIT_SIZE  ( RSA_MODULUS_BYTE_SIZE * 8 )

/****************************************************************************/
/*                                                                          */
/*  Take Ownership of the TPM                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is the authorization data (password) for the new owner         */
/* srkpass   is the authorization data (password) for the new root key      */
/*           if NULL, authorization required flag is turned off             */
/*           both authorization values must be 20 bytes long                */
/* key       a pointer to a keydata structure to receive the SRK public key */
/*           or NULL if this information is not required                    */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_TakeOwnership(unsigned char *ownpass, unsigned char *srkpass,
			   keydata * key)
{
	unsigned char take_owner_fmt[] = "00 c2 T l s @ @ % l % 00 %";
	/* required OAEP padding P parameter */
	unsigned char tpm_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };
	uint32_t ret;
	int iret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	pubkeydata tpmpubkey;	/* public endorsement key data */
	uint32_t srkparamsize;	/* SRK parameter buffer size */
	unsigned char nonceeven[TPM_HASH_SIZE];	/* even nonce (from OIAPopen) */
	RSA *pubkey;		/* PubEK converted to OpenSSL format */
	unsigned char padded[RSA_MODULUS_BYTE_SIZE];	
	keydata srk;		/* key info for SRK */
	unsigned char dummypass[TPM_HASH_SIZE];	/* dummy srk password */
	unsigned char *spass;	/* pointer to srkpass or dummy */
	unsigned int i;

	/* data to be inserted into Take Owner Request Buffer  */
	/* the uint32_t and uint16_t values are stored in network byte order */
	uint32_t command;	/* command ordinal */
	uint16_t protocol;	/* protocol ID */
	uint32_t oencdatasize;	/* owner auth data encrypted size */
	unsigned char ownerencr[RSA_MODULUS_BYTE_SIZE];	
	uint32_t sencdatasize;	/* srk auth data encrypted size */
	unsigned char srkencr[RSA_MODULUS_BYTE_SIZE];	
	unsigned char srk_param_buff[TPM_SRK_PARAM_BUFF_SIZE];	
	uint32_t authhandle;	/* auth handle (from OIAPopen) */
	unsigned char nonceodd[TPM_HASH_SIZE];	/* odd nonce */
	unsigned char authdata[TPM_HASH_SIZE];	/* auth data */

	/* check that parameters are valid */
	if (ownpass == NULL)
		return ERR_NULL_ARG;
	if (srkpass == NULL) {
		memset(dummypass, 0, sizeof dummypass);
		spass = dummypass;
	} else
		spass = srkpass;
	/* set up command and protocol values for TakeOwnership function */
	command = htonl(0x0d);
	protocol = htons(0x05);
	/* get the TPM Endorsement Public Key */
	ret = TPM_ReadPubek(&tpmpubkey);
	if (ret)
		return ret;
	/* convert the public key to OpenSSL format */
	pubkey = TSS_convpubkey(&tpmpubkey);
	if (pubkey == NULL)
		return ERR_CRYPT_ERR;
	memset(ownerencr, 0, sizeof ownerencr);
	memset(srkencr, 0, sizeof srkencr);
	/* Pad and then encrypt the owner data using the RSA public key */
	iret = RSA_padding_add_PKCS1_OAEP(padded, RSA_MODULUS_BYTE_SIZE,
					  ownpass, TPM_HASH_SIZE,
					  tpm_oaep_pad_str,
					  sizeof tpm_oaep_pad_str);
	if (iret == 0)
		return ERR_CRYPT_ERR;
	iret =
	    RSA_public_encrypt(RSA_MODULUS_BYTE_SIZE, padded, ownerencr,
			       pubkey, RSA_NO_PADDING);
	if (iret < 0)
		return ERR_CRYPT_ERR;
	oencdatasize = htonl(iret);
	/* Pad and then encrypt the SRK data using the RSA public key */
	iret = RSA_padding_add_PKCS1_OAEP(padded, RSA_MODULUS_BYTE_SIZE,
					  spass, TPM_HASH_SIZE,
					  tpm_oaep_pad_str,
					  sizeof tpm_oaep_pad_str);
	if (iret == 0)
		return ERR_CRYPT_ERR;
	iret =
	    RSA_public_encrypt(RSA_MODULUS_BYTE_SIZE, padded, srkencr,
			       pubkey, RSA_NO_PADDING);
	if (iret < 0)
		return ERR_CRYPT_ERR;
	sencdatasize = htonl(iret);
	RSA_free(pubkey);
	if (ntohl(oencdatasize) < 0)
		return ERR_CRYPT_ERR;
	if (ntohl(sencdatasize) < 0)
		return ERR_CRYPT_ERR;
	/* fill the SRK-params key structure */
	/* get tpm version */
	ret =
	    TPM_GetCapability(0x00000006, NULL, 0, &(srk.version[0]), &i);
	if (ret != 0)
		return ret;
	srk.keyusage = 0x0011;	/* Storage Key */
	srk.keyflags = 0;
	if (srkpass != NULL)
		srk.authdatausage = 0x01;
	else
		srk.authdatausage = 0x00;
	srk.privkeylen = 0;	/* private key not specified here */
	srk.pub.algorithm = 0x00000001;	/* RSA */
	srk.pub.encscheme = 0x0003;	/* RSA OAEP SHA1 MGF1 */
	srk.pub.sigscheme = 0x0001;	/* NONE */
	srk.pub.keybitlen = RSA_MODULUS_BIT_SIZE;
	srk.pub.numprimes = 2;
	srk.pub.expsize = 0;	/* defaults to 0x010001 */
	srk.pub.keylength = 0;	/* not used here */
	srk.pub.pcrinfolen = 0;	/* not used here */
	/* convert to a memory buffer */
	srkparamsize = TPM_BuildKey(srk_param_buff, &srk);
	/* generate the odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (ret == 0)
		return ret;
	/* initiate the OIAP protocol */
	ret = TSS_OIAPopen(&authhandle, nonceeven);
	if (ret != 0)
		return ret;
	/* calculate the Authorization Data */
	ret =
	    TSS_authhmac(authdata, ownpass, TPM_HASH_SIZE, nonceeven,
			 nonceodd, 0, TPM_U32_SIZE, &command, TPM_U16_SIZE,
			 &protocol, TPM_U32_SIZE, &oencdatasize,
			 ntohl(oencdatasize), ownerencr, TPM_U32_SIZE,
			 &sencdatasize, ntohl(sencdatasize), srkencr,
			 srkparamsize, srk_param_buff, 0, 0);
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* insert all the calculated fields into the request buffer */
	ret = TSS_buildbuff(take_owner_fmt, tpmdata,
			    command,
			    protocol,
			    ntohl(oencdatasize),
			    ownerencr,
			    ntohl(sencdatasize),
			    srkencr,
			    srkparamsize,
			    srk_param_buff,
			    authhandle,
			    TPM_HASH_SIZE,
			    nonceodd, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "Take Ownership");
	TSS_OIAPclose(authhandle);
	if (ret != 0)
		return ret;
	/* check the response HMAC */
	srkparamsize = TSS_KeySize(tpmdata + TPM_DATA_OFFSET);
	ret =
	    TSS_checkhmac1(tpmdata, command, nonceodd, ownpass,
			   TPM_HASH_SIZE, srkparamsize, TPM_DATA_OFFSET, 0,
			   0);
	if (ret != 0)
		return ret;
	/* convert the returned key to a structure */
	if (key == NULL)
		return 0;
	TSS_KeyExtract(tpmdata + TPM_DATA_OFFSET, key);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/*  Clear the TPM                                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is the authorization data (password) for the owner             */
/*           the authorization value must be 20 bytes long                  */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OwnerClear(unsigned char *ownpass)
{
	unsigned char clear_owner_fmt[] = "00 c2 T l l % 00 %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	unsigned char nonceeven[TPM_HASH_SIZE];

	/* fields to be inserted into Owner Clear Request Buffer */
	uint32_t command;
	uint32_t authhandle;
	unsigned char nonceodd[TPM_HASH_SIZE];
	unsigned char authdata[TPM_HASH_SIZE];

	/* check that parameters are valid */
	if (ownpass == NULL)
		return ERR_NULL_ARG;
	command = htonl(91);
	/* generate odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (ret == 0)
		return ret;
	/* start OIAP Protocol */
	ret = TSS_OIAPopen(&authhandle, nonceeven);
	if (ret != 0)
		return ret;
	ret =
	    TSS_authhmac(authdata, ownpass, TPM_HASH_SIZE, nonceeven,
			 nonceodd, 0, TPM_U32_SIZE, &command, 0, 0);
	if (ret != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	ret = TSS_buildbuff(clear_owner_fmt, tpmdata,
			    command,
			    authhandle,
			    TPM_HASH_SIZE,
			    nonceodd, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_OIAPclose(authhandle);
		return ret;
	}
	ret = TPM_Transmit(tpmdata, "Owner Clear");
	TSS_OIAPclose(authhandle);
	return ret;
}
