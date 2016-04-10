/********************************************************************************/
/*										*/
/*			     	TPM Context Management Routines			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: context.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

uint32_t TPM_SaveKeyContext(uint32_t keyhandle,
                            struct tpm_buffer *context)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_SaveKeyContext);
	STACK_TPM_BUFFER(tpmdata)
	uint32_t keyhandle_no = htonl(keyhandle);
	uint32_t len;
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	ret = TSS_buildbuff("00 c1 T l l",&tpmdata,
	                             ordinal_no,
	                               keyhandle_no);
	if (( ret & ERR_MASK )!= 0) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"SaveKeyContext");
	
	if (ret != 0) {
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	if (NULL != context) {
		SET_TPM_BUFFER(context,
			       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
			       len);
	}
	
	return ret;
}


uint32_t TPM_LoadKeyContext(struct tpm_buffer *context,
                            uint32_t *keyhandle)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_LoadKeyContext);
	STACK_TPM_BUFFER(tpmdata);

	ret = TSS_buildbuff("00 c1 T l @",&tpmdata,
	                             ordinal_no,
	                               context->used, context->buffer);
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"LoadKeyContext");
	
	if (ret != 0) {
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, keyhandle);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	return ret;
}




uint32_t TPM_SaveAuthContext(uint32_t authhandle,
                             unsigned char * authContextBlob, uint32_t * authContextSize)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_SaveAuthContext);
	STACK_TPM_BUFFER(tpmdata)
	uint32_t authhandle_no = htonl(authhandle);
	uint32_t len;

	ret = TSS_buildbuff("00 c1 T l l",&tpmdata,
	                             ordinal_no,
	                               authhandle_no);
	if (( ret & ERR_MASK )!= 0) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"SaveAuthContext");
	
	if (ret != 0) {
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &len);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	if (NULL != authContextBlob) {
		*authContextSize = MIN(*authContextSize, len);
		memcpy(authContextBlob,
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
		       *authContextSize);
	}
	
	return ret;
}


uint32_t TPM_LoadAuthContext(unsigned char *authContextBlob, uint32_t authContextSize,
                             uint32_t *authhandle)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_LoadAuthContext);
	STACK_TPM_BUFFER(tpmdata);

	ret = TSS_buildbuff("00 c1 T l @",&tpmdata,
	                             ordinal_no,
	                               authContextSize, authContextBlob);
	if ( ( ret & ERR_MASK ) != 0) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"LoadAuthContext");
	
	if (ret != 0) {
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, authhandle);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	return ret;
}
