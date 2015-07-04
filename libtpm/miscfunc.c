/*
 * libtpm: misc routines
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

#define TPM_OWNER_ETYPE 0x0002
#define TPM_OWNER_EVALUE 0x40000001

/****************************************************************************/
/*                                                                          */
/*  GetCapabilityOwner                                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_GetCapabilityOwner(unsigned char *ownpass,
				uint32_t * volflags, uint32_t * nvolflags)
{
	unsigned char getcap_owner_fmt[] = "00 c2 T l l % 00 %";
	uint32_t ret;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	/* data to be inserted into Request Buffer (in Network Byte Order) 
	 * the uint32_t and uint16_t values are stored in network byte order
	 * are in the correct format when being hashed by the HMAC 
         */
	uint32_t command;	/* command ordinal */
	unsigned char nonceodd[TPM_HASH_SIZE];	/* odd nonce */
	unsigned char authdata[TPM_HASH_SIZE];	/* auth data */
	osapsess sess;

	/* check that parameters are valid */
	if (ownpass == NULL || volflags == NULL || nvolflags == NULL)
		return ERR_NULL_ARG;
	/* set up command and protocol values for TakeOwnership function */
	command = htonl(0x66);
	/* generate the odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (ret == 0)
		return ret;
	/* initiate the OSAP protocol */
	ret =
	    TSS_OSAPopen(&sess, ownpass, TPM_OWNER_ETYPE,
			 TPM_OWNER_EVALUE);
	if (ret != 0)
		return ret;
	/* calculate the Authorization Data */
	ret =
	    TSS_authhmac(authdata, sess.ssecret, 20, sess.enonce, nonceodd,
			 0, TPM_U32_SIZE, &command, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* insert all the calculated fields into the request buffer */
	ret = TSS_buildbuff(getcap_owner_fmt, tpmdata,
			    command,
			    sess.handle,
			    TPM_HASH_SIZE,
			    nonceodd, TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "GetCapabilityOwner");
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	ret =
	    TSS_checkhmac1(tpmdata, command, nonceodd, sess.ssecret,
			   TPM_HASH_SIZE, 4, TPM_DATA_OFFSET, TPM_U32_SIZE,
			   TPM_DATA_OFFSET + 4, TPM_U32_SIZE,
			   TPM_DATA_OFFSET + 4 + TPM_U32_SIZE, 0, 0);
	if (ret != 0) {
		TSS_OSAPclose(&sess);
		return ret;
	}
	TSS_OSAPclose(&sess);
	*nvolflags = LOAD32(tpmdata, TPM_DATA_OFFSET + 4);
	*volflags = LOAD32(tpmdata, TPM_DATA_OFFSET + 4 + TPM_U32_SIZE);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/*  GetCapability                                                           */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_GetCapability(uint32_t caparea, unsigned char *subcap,
			   int subcaplen, unsigned char *resp,
			   unsigned int *resplen)
{
	unsigned char getcap_fmt[] = "00 c1 T 00 00 00 65 L @";
	uint32_t ret;
	uint32_t rlen;
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];

	/* check arguments */
	if (subcaplen > 0 && subcap == NULL)
		return ERR_NULL_ARG;
	if (resp == NULL || resplen == NULL)
		return ERR_NULL_ARG;
	ret =
	    TSS_buildbuff(getcap_fmt, tpmdata, caparea, subcaplen, subcap);
	if ((ret & ERR_MASK) != 0)
		return ret;
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata, "GetCapability");
	if (ret != 0)
		return ret;
	rlen = LOAD32(tpmdata, TPM_DATA_OFFSET);
	memcpy(resp, tpmdata + TPM_DATA_OFFSET + TPM_U32_SIZE, rlen);
	*resplen = rlen;
	return 0;
}

/****************************************************************************/
/*                                                                          */
/*  Reset TPM                                                               */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Reset()
{
	unsigned char tpmdata[] = {
		0, 193,		/*TPM_TAG_RQU_COMMAND */
		0, 0, 0, 10,	/* blob length, bytes */
		0, 0, 0, 90
	};
	return TPM_Transmit(tpmdata, "Reset");
}

/****************************************************************************/
/*                                                                          */
/*  Convert Error code to message                                           */
/*                                                                          */
/****************************************************************************/
static unsigned char *msgs[] = {
	"Unknown error",
	"Authentication failed (Incorrect Password)",
	"Illegal PCR index",
	"Bad parameter",
	"Auditing failure",
	"Clear disabled",
	"TPM deactivated",
	"TPM disabled",
	"Target command disabled",
	"Operation failed",
	"Ordinal unknown",
	"Owner installation disabled",
	"Invalid key handle",
	"Target key not found",
	"Unacceptable encryption scheme",
	"Migration authorization failed",
	"PCR information incorrect",
	"No room to load key",
	"No SRK set",
	"Encrypted blob invalid",
	"TPM already has owner",
	"TPM out of resources",
	"Random string too short",
	"TPM out of space",
	"PCR mismatch",
	"Paramsize mismatch",
	"No existing SHA-1 thread",
	"SHA-1 thread error",
	"TPM self test failed - TPM shutdown",
	"Authorization failure for 2nd key",
	"Invalid tag value",
	"TPM I/O error",
	"Encryption error",
	"Decryption failure",
	"Invalid handle",
	"TPM has no endorsement key",
	"Invalid key usage",
	"Invalid entity type",
	"Incorrect command sequence",
	"Inappropriate signature data",
	"Unsupported key properties",
	"Incorrect migration properties",
	"Incorrect signature or encryption scheme",
	"Incorrect data size",
	"Incorrect mode parameter",
	"Invalid presence values",
	"Incorrect version"
};

static unsigned char *msgs2[] = {
	"Format error in TPM response",
	"HMAC authorization verification failed",
	"NULL argument",
	"Invalid argument",
	"Error from OpenSSL library",
	"I/O error",
	"Memory allocation error"
};

unsigned char *TPM_GetErrMsg(uint32_t code)
{
	if (code == ERR_BAD_RESP)
		return msgs2[0];
	if (code == ERR_HMAC_FAIL)
		return msgs2[1];
	if (code == ERR_NULL_ARG)
		return msgs2[2];
	if (code == ERR_BAD_ARG)
		return msgs2[3];
	if (code == ERR_CRYPT_ERR)
		return msgs2[4];
	if (code == ERR_IO)
		return msgs2[5];
	if (code == ERR_MEM_ERR)
		return msgs2[6];
	if (code < 1 || code > 46)
		return msgs[0];
	return msgs[code];
}
