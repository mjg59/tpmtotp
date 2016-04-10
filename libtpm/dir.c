/********************************************************************************/
/*										*/
/*			     	TPM Dir Routines				*/
/*			     Written by S. Berger 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: dir.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

uint32_t TPM_DirWriteAuth(uint32_t dirIndex,
                          unsigned char * newValue,
                          unsigned char * ownerAuth)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ordinal_no = htonl(TPM_ORD_DirWriteAuth);
	uint32_t ret;
	uint32_t dirIndex_no = htonl(dirIndex);

	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	session sess;
	int c = 0;
	
	/* check input arguments */
	if (NULL == ownerAuth ||
	    NULL == newValue) {
		return ERR_NULL_ARG;
	}
	

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP | SESSION_OIAP,
	                      &sess,
	                      ownerAuth, TPM_ET_OWNER, 0);

	if (ret != 0) 
		return ret;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) 
		return ERR_CRYPT_ERR;

	/* move Network byte order data to variable for HMAC calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE,&ordinal_no,
	                   TPM_U32_SIZE,&dirIndex_no,
	                   TPM_HASH_SIZE, newValue,
	                   0,0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l % L % o %", &tpmdata,
	                             ordinal_no,
	                               dirIndex_no,
	                                 TPM_HASH_SIZE, newValue,
	                                   TSS_Session_GetHandle(&sess),
	                                     TPM_HASH_SIZE, nonceodd,
	                                       c,
	                                         TPM_HASH_SIZE, authdata);
		

	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"DirWriteAuth");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}
	/* check the HMAC in the response */

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     0,0);

	return ret;
}


uint32_t TPM_DirRead(uint32_t dirIndex,
                     unsigned char * dirValueBuffer) 
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_DirRead);
	STACK_TPM_BUFFER(tpmdata)
	uint32_t dirIndex_no = htonl(dirIndex);
	
	ret = TSS_buildbuff("00 c1 T l l",&tpmdata,
	                             ordinal_no,
	                               dirIndex_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"DirRead");
	
	if (ret != 0) {
		return ret;
	}

	if (tpmdata.used != 30) {
		ret = ERR_BAD_RESP;
	}

	if (NULL != dirValueBuffer) {
		memcpy(dirValueBuffer, 
		       &tpmdata.buffer[TPM_DATA_OFFSET], 
		       20);
	}
	
	return ret;
}
