/********************************************************************************/
/*										*/
/*			     	TPM Administrative Routines			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: management.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <tpmfunc.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tpm_types.h>
#include <tpm_constants.h>


uint32_t TPM_SetRedirection(uint32_t keyhandle,
                            uint32_t redirCmd,
                            unsigned char * inputData, uint32_t inputDataSize,
                            unsigned char * ownerAuth,
                            unsigned char * usageAuth)
{
	uint32_t ret = 0;
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_HASH_SIZE];			  /* odd nonce */
	unsigned char authdata[TPM_HASH_SIZE];			  /* auth data */
	session sess;
	uint32_t ordinal_no = htonl(TPM_ORD_SetRedirection);
	uint32_t redirCmd_no = htonl(redirCmd);
	uint32_t inputDataSize_no = htonl(inputDataSize);
	uint32_t keyHandle_no = htonl(keyhandle);
	TPM_BOOL c = FALSE;
	(void)usageAuth;	

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	/* generate the odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (ret == 0) 
		return ret;

	/* initiate the OSAP protocol */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP,&sess,ownerAuth,TPM_ET_OWNER,keyhandle);
	if (ret != 0) {
		return ret;
	}
	/* calculate the Authorization Data */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,0,
	                   TPM_U32_SIZE,&ordinal_no,
	                   TPM_U32_SIZE,&redirCmd_no,
	                   TPM_U32_SIZE,&inputDataSize_no,
	                   inputDataSize, inputData,
	                   0,0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}

	/* insert all the calculated fields into the request buffer */
	ret = TSS_buildbuff("00 c2 T l l l @ L % o %",&tpmdata,
	                             ordinal_no,
	                               keyHandle_no,
	                                 redirCmd_no,
	                                   inputDataSize, inputData,
	                                     TSS_Session_GetHandle(&sess),
	                                       TPM_HASH_SIZE, nonceodd,
	                                         c,
	                                           TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"SetRedirection");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     0,0);

	return ret;
}

uint32_t TPM_ResetLockValue(unsigned char * ownerAuth)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ordinal_no = htonl(TPM_ORD_ResetLockValue);
	uint32_t ret;
	
	/* check input arguments */

	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	TPM_BOOL c = 0;
	session sess;


	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) 
		return ERR_CRYPT_ERR;

	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      ownerAuth, TPM_ET_OWNER, 0);

	if (ret != 0) 
		return ret;

	/* move Network byte order data to variable for hmac calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE,&ordinal_no,
	                   0,0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l L % o %", &tpmdata,
	                             ordinal_no,
	                               TSS_Session_GetHandle(&sess),
	                                 TPM_HASH_SIZE, nonceodd,
	                                   c,
	                                     TPM_HASH_SIZE, authdata);
		

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"ResetLockValue");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}
	/* check the HMAC in the response */
	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     0,0);

	return ret;
}
