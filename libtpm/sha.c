/********************************************************************************/
/*										*/
/*			     	TPM SHA Digest Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: sha.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

/****************************************************************************/
/*                                                                          */
/* Start a SHA1 Digest					                    */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_SHA1Start(uint32_t *maxNumBytes) {
	uint32_t ordinal_no;
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	/* move Network byte order data to variable for hmac calculation */
	ordinal_no = htonl(TPM_ORD_SHA1Start);

	TSS_buildbuff("00 c1 T l", &tpmdata,
	                       ordinal_no);
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"SHA1Start");

	if (ret != 0) {
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, maxNumBytes);

	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Do a SHA1 Update					                    */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* data       : A block of data whose size must be a multiple of 64         */
/* datalen    : The length of the data block                                */
/****************************************************************************/
uint32_t TPM_SHA1Update(void * data, uint32_t datalen) {
	uint32_t ordinal_no;
	uint32_t ret;
	struct tpm_buffer *tpmdata = TSS_AllocTPMBuffer(datalen+20);
	/* move Network byte order data to variable for hmac calculation */
	ordinal_no = htonl(TPM_ORD_SHA1Update);
	
	if (NULL == tpmdata) {
		return ERR_BAD_SIZE;
	}

	ret = TSS_buildbuff("00 c1 T l @", tpmdata,
	                             ordinal_no,
	                               datalen, data);
	if (ret & ERR_MASK) {
		goto err_exit;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata,"SHA1Update");

err_exit:	
	TSS_FreeTPMBuffer(tpmdata);

	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Do a SHA1 Complete					                    */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* data       : A block of data whose size must be 64 or less               */
/* datalen    : The length of the data block                                */
/* hash       : A block of size TPM_HASH_SIZE (=20) to hold the SHA1 hash   */
/****************************************************************************/
uint32_t TPM_SHA1Complete(void *data, uint32_t datalen,
                          unsigned char * hash) {
	uint32_t ordinal_no;
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)

	/* move Network byte order data to variable for hmac calculation */
	ordinal_no = htonl(TPM_ORD_SHA1Complete);

	TSS_buildbuff("00 c1 T l @", &tpmdata,
	                       ordinal_no,
	                         datalen, data);

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"SHA1Complete");

	if (0 != ret) {
		return ret;
	}
	
	memcpy(hash, 
	       &tpmdata.buffer[TPM_DATA_OFFSET],
	       TPM_HASH_SIZE);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Do a SHA1 Complete Extend 				                    */
/*                                                                          */
/* The arguments are ...                                                    */
/*                                                                          */
/* data       : A block of data whose size must be 64 or less               */
/* datalen    : The length of the data block                                */
/* pcrNum     : The index of the CPR to be modified                         */
/* hash       : A block of size TPM_HASH_SIZE (=20) to hold the SHA1 hash   */
/* pcrValue   : A block of size TPM_HASH_SIZE (=20) to hold the PCR value   */
/****************************************************************************/
uint32_t TPM_SHA1CompleteExtend(void *data, uint32_t datalen,
                                uint32_t pcrNum,
                                unsigned char * hash,
                                unsigned char * pcrValue) 
{
	uint32_t ordinal_no;
	uint32_t pcrNum_no = htonl(pcrNum);
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)

	/* move Network byte order data to variable for hmac calculation */
	ordinal_no = htonl(TPM_ORD_SHA1CompleteExtend);

	TSS_buildbuff("00 c1 T l l @", &tpmdata,
	                       ordinal_no,
	                         pcrNum_no,
	                           datalen, data);

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"SHA1CompleteExtend");

	if (0 != ret) {
		return ret;
	}
	
	memcpy(hash, 
	       &tpmdata.buffer[TPM_DATA_OFFSET],
	       TPM_HASH_SIZE);
	       
	memcpy(pcrValue,
	       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_HASH_SIZE],
	       TPM_HASH_SIZE);

	return ret;
}
