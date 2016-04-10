/********************************************************************************/
/*										*/
/*			     	TPM DAA Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: daa.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

uint32_t TPM_DAA_Join(uint32_t sesshandle,
                      unsigned char * ownerauth,    // HMAC key
                      unsigned char stage,
                      unsigned char * inputData0, uint32_t inputData0Size,
                      unsigned char * inputData1, uint32_t inputData1Size, 
                      unsigned char * outputData, uint32_t * outputDataSize
                      )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_DAA_Join);
	uint32_t sesshandle_no = htonl(sesshandle);
	uint32_t inputData0Size_no = htonl(inputData0Size);
	uint32_t inputData1Size_no = htonl(inputData1Size);
	uint32_t ret;
	uint32_t len;
	session sess;
	 
	/* check input arguments */
	if (NULL == inputData0) {
		inputData0Size = 0;
	}
	if (NULL == inputData1) {
		inputData1Size = 0;
	}

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) return ERR_CRYPT_ERR;
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      ownerauth, TPM_ET_OWNER, 0);
	if (ret != 0) return ret;
	/* move Network byte order data to variable for HMAC calculation */

	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE, &ordinal_no,
	                   sizeof(BYTE), &stage,
	                   TPM_U32_SIZE, &inputData0Size_no,
	                   inputData0Size, inputData0,
	                   TPM_U32_SIZE, &inputData1Size_no,
	                   inputData1Size, inputData1,
	                   0,0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l o @ @ L % o %", &tpmdata,
	                             ordinal_no,
	                               sesshandle_no,
	                                 stage,
	                                   inputData0Size, inputData0,
	                                     inputData1Size, inputData1,
	                                       TSS_Session_GetHandle(&sess),
	                                         TPM_NONCE_SIZE,nonceodd,
	                                           c,
	                                             TPM_HASH_SIZE,authdata);

	if ( 0 != (ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata,"TPM_DAA_Join - AUTH1");
	TSS_SessionClose(&sess);

	if (0 != ret) {
		return ret;
	}

	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     TPM_U32_SIZE + len, TPM_DATA_OFFSET,
	                     0,0);

	if (0 != ret) {
		return ret;
	}
	
	if (NULL != outputData) {
		*outputDataSize = MIN(*outputDataSize, len);
		memcpy(outputData, 
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE] , 
		       *outputDataSize);
	}

	return ret;
}



uint32_t TPM_DAA_Sign(uint32_t sesshandle,
                      unsigned char * ownerauth,    // HMAC key
                      unsigned char stage,
                      unsigned char * inputData0, uint32_t inputData0Size,
                      unsigned char * inputData1, uint32_t inputData1Size, 
                      unsigned char * outputData, uint32_t * outputDataSize
                      )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_DAA_Sign);
	uint32_t sesshandle_no = htonl(sesshandle);
	uint32_t inputData0Size_no = htonl(inputData0Size);
	uint32_t inputData1Size_no = htonl(inputData1Size);
	uint32_t ret;
	uint32_t len;
	session sess;
	 
	/* check input arguments */
	if (NULL == inputData0) {
		inputData0Size = 0;
	}
	if (NULL == inputData1) {
		inputData1Size = 0;
	}

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) return ERR_CRYPT_ERR;
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      ownerauth, TPM_ET_OWNER, 0);
	if (ret != 0) return ret;
	/* move Network byte order data to variable for HMAC calculation */

	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE, &ordinal_no,
	                   sizeof(BYTE), &stage,
	                   TPM_U32_SIZE, &inputData0Size_no,
	                   inputData0Size, inputData0,
	                   TPM_U32_SIZE, &inputData1Size_no,
	                   inputData1Size, inputData1,
	                   0,0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l o @ @ L % o %", &tpmdata,
	                             ordinal_no,
	                               sesshandle_no,
	                                 stage,
	                                   inputData0Size, inputData0,
	                                     inputData1Size, inputData1,
	                                       TSS_Session_GetHandle(&sess),
	                                         TPM_NONCE_SIZE,nonceodd,
	                                           c,
	                                             TPM_HASH_SIZE,authdata);

	if ( 0 != (ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata,"TPM_DAA_Join");

	TSS_SessionClose(&sess);
	if (0 != ret) {
		return ret;
	}

	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     TPM_U32_SIZE + len, TPM_DATA_OFFSET,
	                     0,0);

	if (0 != ret) {
		return ret;
	}
	
	if (NULL != outputData) {
		*outputDataSize = MIN(*outputDataSize, len);
		memcpy(outputData, 
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE], 
		       *outputDataSize);
	}

	return ret;
}
