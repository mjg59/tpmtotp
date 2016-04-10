/********************************************************************************/
/*										*/
/*			     	TPM Testing Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: optin.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

uint32_t TPM_SetOwnerInstall(TPM_BOOL state)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_SetOwnerInstall);
	STACK_TPM_BUFFER(tpmdata)

	ret = TSS_buildbuff("00 c1 T l o",&tpmdata,
	                             ordinal_no,
	                               state);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"SetOwnerInstall");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}


uint32_t TPM_OwnerSetDisable(unsigned char *ownerauth,
                             TPM_BOOL state)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_OwnerSetDisable);
	uint32_t ret;
	session sess;
	
	/* check input arguments */
	if (NULL == ownerauth) return ERR_NULL_ARG;


	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) 
		return ERR_CRYPT_ERR;

	/* Open Session */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      ownerauth, TPM_ET_OWNER, 0);
	if (ret != 0) 
		return ret;
	

	/* move Network byte order data to variable for hmac calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE,&ordinal_no,
	                   sizeof(TPM_BOOL),&state,
	                   0,0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l o L % o %", &tpmdata,
	                             ordinal_no,
	                               state,
	                                 TSS_Session_GetHandle(&sess),
	                                   TPM_NONCE_SIZE,nonceodd,
	                                     c,
	                                       TPM_HASH_SIZE,authdata);
	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"OwnerSetDisable");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}
	/* check the HMAC in the response */
		
	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     0,0);
	
	return ret;
}


uint32_t TPM_SetTempDeactivated(unsigned char *operatorauth  // HMAC key
                            )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_SetTempDeactivated);
	uint32_t ret;
	
	/* check input arguments */


	if (NULL != operatorauth) {
		/* Open OIAP Session */
		session sess;
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
		                      &sess,
		                      operatorauth, TPM_ET_OWNER, 0);
		if (ret != 0) 
			return ret;
		/* calculate encrypted authorization value */
		
		/* generate odd nonce */
		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) 
			return ERR_CRYPT_ERR;
		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal_no,
		                   0,0);

		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l L % o %", &tpmdata,
		                             ordinal_no,
		                               TSS_Session_GetHandle(&sess),
		                                 TPM_NONCE_SIZE,nonceodd,
		                                   c,
		                                     TPM_HASH_SIZE,authdata);
		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"SetTempDeactivated - AUTH1");

		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}

		/* check the HMAC in the response */
		
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     0,0);
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l", &tpmdata,
		                             ordinal_no);

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"SetTempDeactivated");
	}
		
	return ret;
}



uint32_t TPM_PhysicalEnable()
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_PhysicalEnable);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l",&tpmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"PhysicalEnable");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}

uint32_t TPM_PhysicalDisable()
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_PhysicalDisable);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l",&tpmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"PhysicalDisable");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}


uint32_t TPM_PhysicalSetDeactivated(TPM_BOOL state)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_PhysicalSetDeactivated);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l o",&tpmdata,
	                             ordinal_no,
	                               state);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"PhysicalSetDeactivated");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}


uint32_t TPM_SetOperatorAuth(unsigned char * operatorAuth)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_SetOperatorAuth);
	STACK_TPM_BUFFER(tpmdata)
	
	if (NULL == operatorAuth) return ERR_NULL_ARG;
	
	ret = TSS_buildbuff("00 c1 T l %",&tpmdata,
	                             ordinal_no,
	                               TPM_HASH_SIZE, operatorAuth);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"SetOperatorAuth");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}
