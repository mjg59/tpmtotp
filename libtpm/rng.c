/********************************************************************************/
/*										*/
/*			     	TPM Random Number Generator Routines		*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: rng.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
/*  Get Random Number                                                       */
/*                                                                          */
/*  The parameters are...                                                   */
/*                                                                          */
/*  numbytes : The number of bytes requested                                */
/*  buffer   : a buffer to hold the amount of requested bytes               */
/*  bytesret : The actual number of bytes that were returned                */
/****************************************************************************/
uint32_t TPM_GetRandom(uint32_t bytesreq,
                       unsigned char * buffer, uint32_t * bytesret)
{
	uint32_t ret;
	STACK_TPM_BUFFER( tpmdata )
	
	uint32_t ordinal_no = htonl(TPM_ORD_GetRandom);
	uint32_t numbytes_no = htonl(bytesreq);

	TSS_buildbuff("00 c1 T l l",&tpmdata,
	                       ordinal_no,
	                         numbytes_no);

	ret = TPM_Transmit(&tpmdata,"GetRandom");

	if (0 != ret) {
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, bytesret);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	memcpy(buffer,
	       &tpmdata.buffer[TPM_DATA_OFFSET + TPM_U32_SIZE],
	       *bytesret);
	
	return ret;
}



/****************************************************************************/
/*                                                                          */
/*  Stir Random Number Generator                                            */
/*                                                                          */
/*  The parameters are...                                                   */
/*                                                                          */
/*  data    : Data to add entropy to the random number generator's state    */
/*  datalen : The number of bytes; must be < 256                            */
/****************************************************************************/
uint32_t TPM_StirRandom(unsigned char * data, uint32_t datalen) 
{
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ordinal_no = htonl(TPM_ORD_StirRandom);

	TSS_buildbuff("00 c1 T l @",&tpmdata,
	                       ordinal_no,
	                         (datalen & 0xff), data);

	ret = TPM_Transmit(&tpmdata,"StirRandom");
	return ret;
}

