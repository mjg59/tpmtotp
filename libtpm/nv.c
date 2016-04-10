/********************************************************************************/
/*										*/
/*			     	TPM NV Storage Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*        $Id: nv.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
/* Define an area in NV RAM space                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   The sha'ed owner password of the TPM                           */
/* pubInfo   The serialized TPM_NV_DATA_PUBLIC structure with the following */
/*           fields filled out to define the space:                         */
/*           - index                                                        */
/*           - dataSize                                                     */
/*           - permission.attributes                                        */
/*           The pubInfo should be serialized using the TPM_CreatePubInfo   */
/*           function with the buffer size for the serialized structure     */
/*           of exactly TPM_PUBINFO_SERIAL_SIZE bytes.                      */
/* areaauth  The sha'ed area password for access to the defined space       */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_NV_DefineSpace(unsigned char *ownauth,  // HMAC key
                            unsigned char *pubInfo, uint32_t pubInfoSize,
                            unsigned char *areaauth   // used to create  encAuth
                            )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char encauth[TPM_HASH_SIZE];
	unsigned char dummy[TPM_HASH_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_NV_DefineSpace);
	uint32_t ret;
	unsigned char *passptr1;	
	session sess;
	
	memset(dummy,0x0,sizeof(dummy));
	
	/* check input arguments */
	if (NULL == pubInfo) return ERR_NULL_ARG;

	if (NULL != areaauth)
		passptr1 = areaauth;
	else
		passptr1 = dummy;
	
	if (NULL != ownauth) {

		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP,&sess,ownauth,TPM_ET_OWNER,0);
		if (ret != 0) return ret;
		/* calculate encrypted authorization value */
		TPM_CreateEncAuth(&sess, passptr1, encauth, 0);

		/* generate odd nonce */
		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) 
			return ERR_CRYPT_ERR;

		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal_no,
		                   pubInfoSize,pubInfo,
		                   TPM_HASH_SIZE,encauth,
		                   0,0);

		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l % % L % o %", &tpmdata,
		                             ordinal_no,
		                               pubInfoSize, pubInfo,
		                                 TPM_HASH_SIZE, encauth,
		                                   TSS_Session_GetHandle(&sess),
		                                     TPM_NONCE_SIZE,nonceodd,
		                                       c,
		                                         TPM_HASH_SIZE,authdata);
		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"NV_DefineSpace - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		/* check the HMAC in the response */
		
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     0,0);
	} else {

		ret = TSS_buildbuff("00 c1 T l % %", &tpmdata,
		                             ordinal_no,
		                               pubInfoSize, pubInfo,
		                                 TPM_HASH_SIZE, dummy);
		if (0 != (ret & ERR_MASK)) {
			return ret;
		}

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"NV_DefineSpace");
		if (0 != ret ) {
			return ret;
		}
	}
	
	return ret;

}


/****************************************************************************/
/*                                                                          */
/* Define an area in NV RAM space                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownauth   The sha'ed owner password of the TPM                           */
/* index     The index of the area to define                                */
/* dataSize  The size of the area to define                                 */
/* permissions  The permission flags for the area                           */
/* areaauth  The sha'ed area password for access to the defined space       */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_NV_DefineSpace2(unsigned char *ownauth,  // HMAC key
                             uint32_t index,
                             uint32_t size,
                             uint32_t permissions,
                             unsigned char *areaauth,   // used to create  encAuth
			     TPM_PCR_INFO_SHORT *pcrInfoRead,
			     TPM_PCR_INFO_SHORT *pcrInfoWrite)
{
	uint32_t ret;
	uint32_t serDataPublicSize = 0;
	STACK_TPM_BUFFER(pubInfo)
	TPM_NV_DATA_PUBLIC public;
	memset(&public, 0x0, sizeof(public));

	public.tag = TPM_TAG_NV_DATA_PUBLIC;
	public.nvIndex = index;

	if (pcrInfoRead != NULL) {
	    public.pcrInfoRead.localityAtRelease = pcrInfoRead->localityAtRelease;
	    public.pcrInfoRead.pcrSelection.sizeOfSelect = pcrInfoRead->pcrSelection.sizeOfSelect;
	    memcpy(public.pcrInfoRead.pcrSelection.pcrSelect, pcrInfoRead->pcrSelection.pcrSelect,
		   pcrInfoRead->pcrSelection.sizeOfSelect);
	    memcpy(public.pcrInfoRead.digestAtRelease, pcrInfoRead->digestAtRelease,
		   TPM_HASH_SIZE);
	}
	else {
	    public.pcrInfoRead.pcrSelection.sizeOfSelect = 3;
	    public.pcrInfoRead.localityAtRelease = TPM_LOC_ZERO;
	    /* other fields remain 0 */
	}
	
	if (pcrInfoWrite!= NULL) {
	    public.pcrInfoWrite.localityAtRelease = pcrInfoWrite->localityAtRelease;
	    public.pcrInfoWrite.pcrSelection.sizeOfSelect = pcrInfoWrite->pcrSelection.sizeOfSelect;
	    memcpy(public.pcrInfoWrite.pcrSelection.pcrSelect, pcrInfoWrite->pcrSelection.pcrSelect,
		   pcrInfoWrite->pcrSelection.sizeOfSelect);
	    memcpy(public.pcrInfoWrite.digestAtRelease, pcrInfoWrite->digestAtRelease,
		   TPM_HASH_SIZE);
	    
	}
	else {
	    public.pcrInfoWrite.pcrSelection.sizeOfSelect = 3;
	    public.pcrInfoWrite.localityAtRelease = TPM_LOC_ZERO;
	    /* other fields remain 0 */
	}
	public.permission.tag = TPM_TAG_NV_ATTRIBUTES;
	public.permission.attributes= permissions;
	public.dataSize = size;
	
	ret = TPM_WritePubInfo(&public,&pubInfo);
	if ( (ret & ERR_MASK) != 0 ) {
		return ret;
	}
	serDataPublicSize = ret;
	return TPM_NV_DefineSpace(
	                          ownauth,
	                          pubInfo.buffer, serDataPublicSize,
	                          areaauth);
}



/****************************************************************************/
/*                                                                          */
/* Write a value into NV RAM space                                          */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* nvIndex     The index of a previously defined area                       */
/* offset      The offset into the area where to start writing              */
/* data        Pointer to the data to write to the area                     */
/* datalen     The length of the data to write                              */
/* ownauth     The sha'ed owner password of the TPM                         */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_NV_WriteValue(uint32_t nvIndex,
                           uint32_t offset,
                           unsigned char *data, uint32_t datalen,
                           unsigned char *ownauth  // HMAC key
                           )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_NV_WriteValue);
	uint32_t ret;
	uint32_t datalen_no = htonl(datalen);
	uint32_t nvIndex_no = htonl(nvIndex);
	uint32_t offset_no  = htonl(offset);
	 

	/* check input arguments */
/* 	if (data == NULL) return ERR_NULL_ARG; */

	if (NULL != ownauth) {
		/* generate odd nonce */
		session sess;
		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) 
			return ERR_CRYPT_ERR;
		/* Open OIAP Session */
		
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
		                      &sess,
		                      ownauth, TPM_ET_OWNER,0);
		if (0 != ret) {
			return ret;
		}
		/* move Network byte order data to variable for hmac calculation */
		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_U32_SIZE, &nvIndex_no,
		                   TPM_U32_SIZE, &offset_no,
		                   TPM_U32_SIZE, &datalen_no,
		                   datalen     , data,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
	
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l l @ L % o %", &tpmdata,
		                             ordinal_no,
		                               nvIndex_no,
		                                 offset_no,
		                                   datalen, data,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_NONCE_SIZE,nonceodd,
		                                         c,
		                                           TPM_HASH_SIZE,authdata);

		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"NV_WriteValue");

		TSS_SessionClose(&sess);
		if (0 != ret) {
			return ret;
		}

		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     0,0);

		if (0 != ret) {
			return ret;
		}
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l l @", &tpmdata,
		                             ordinal_no,
		                               nvIndex_no,
		                                 offset_no,
		                                   datalen, data);

		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"NV_WriteValue");
		if (0 != ret ) {
			return ret;
		}

	}

	return ret;	
}

/****************************************************************************/
/*                                                                          */
/* Write a value into password protected NV RAM space                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* nvIndex     The index of a previously defined area                       */
/* offset      The offset into the area where to start writing              */
/* data        Pointer to the data to write to the area                     */
/* datalen     The length of the data to write                              */
/* areaauth    The sha'ed storage area password                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_NV_WriteValueAuth(uint32_t nvIndex,
                               uint32_t offset,
                               unsigned char *data, uint32_t datalen,
                               unsigned char * areaauth  // key for area
                               ) 
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_NV_WriteValueAuth);
	uint32_t ret;
	uint32_t datalen_no = htonl(datalen);
	uint32_t nvIndex_no = htonl(nvIndex);
	uint32_t offset_no  = htonl(offset);
	session sess;
	 

	/* check input arguments */
	if (areaauth == NULL) return ERR_NULL_ARG;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) return ERR_CRYPT_ERR;
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      areaauth, TPM_ET_NV, nvIndex);
	                      
	if (ret != 0) 
		return ret;
	/* move Network byte order data to variable for hmac calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE, &ordinal_no,
	                   TPM_U32_SIZE, &nvIndex_no,
	                   TPM_U32_SIZE, &offset_no,
	                   TPM_U32_SIZE, &datalen_no,
	                   datalen     , data,
	                   0,0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l l @ L % o %", &tpmdata,
	                             ordinal_no,
	                               nvIndex_no,
	                                 offset_no,
	                                   datalen, data,
	                                     TSS_Session_GetHandle(&sess),
	                                       TPM_NONCE_SIZE,nonceodd,
	                                         c,
	                                           TPM_HASH_SIZE,authdata);

	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata,"NV_WriteValueAuth - AUTH1");

	TSS_SessionClose(&sess);

	if (0 != ret) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     0,0);

	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Read a value from NV RAM space                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* nvIndex     The index of a previously defined area                       */
/* offset      The offset into the area where to start reading              */
/* datasize    The number of bytes to read from  the area                   */
/* buffer      The buffer to hold the data                                  */
/* buffersize  On input: contains the size of the buffer and on output will */
/*             hold the actual number of bytes that have been read          */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_NV_ReadValue(uint32_t nvIndex,
                          uint32_t offset,
                          uint32_t datasize,
                          unsigned char * buffer, uint32_t * buffersize,
                          unsigned char *ownauth  // HMAC key
                          )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_NV_ReadValue);
	uint32_t ret;
	uint32_t len;
	uint32_t datasize_no= htonl(datasize);
	uint32_t nvIndex_no = htonl(nvIndex);
	uint32_t offset_no  = htonl(offset);
	 

	/* check input arguments */
	if (buffer == NULL) return ERR_NULL_ARG;

	if (NULL != ownauth) {
		session sess;
		/* generate odd nonce */
		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) 
			return ERR_CRYPT_ERR;
		/* Open OIAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
		                      &sess,
		                      ownauth, TPM_ET_OWNER, nvIndex);
		if (ret != 0) 
			return ret;
		/* move Network byte order data to variable for hmac calculation */
		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_U32_SIZE, &nvIndex_no,
		                   TPM_U32_SIZE, &offset_no,
		                   TPM_U32_SIZE, &datasize_no,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
	
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l l l L % o %", &tpmdata,
		                             ordinal_no,
		                               nvIndex_no,
		                                 offset_no,
		                                   datasize_no,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_NONCE_SIZE,nonceodd,
		                                         c,
		                                           TPM_HASH_SIZE,authdata);

		if ((ret & ERR_MASK)) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"NV_ReadValue - AUTH1");
		TSS_SessionClose(&sess);

		if (0 != ret) {
			return ret;
		}
	
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     TPM_U32_SIZE + len, TPM_DATA_OFFSET,
		                     0,0);

		if (0 != ret) {
			return ret;
		}
	
		*buffersize = MIN(*buffersize, len);
		memcpy(buffer, &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE], *buffersize);
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l l l", &tpmdata,
		                             ordinal_no,
		                               nvIndex_no,
		                                 offset_no,
		                                   datasize_no);

		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TPM_Transmit(&tpmdata,"NV_ReadValue");

		if (0 != ret) {
			return ret;
		}
	
		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &len);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		*buffersize = MIN(*buffersize, len);
		memcpy(buffer, &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE], *buffersize);
	}
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Read a value from password protected NV RAM space                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* nvIndex     The index of a previously defined area                       */
/* offset      The offset into the area where to start reading              */
/* datasize    The number of bytes to read from  the area                   */
/* buffer      The buffer to hold the data                                  */
/* buffersize  On input: contains the size of the buffer and on output will */
/*             hold the actual number of bytes that have been read          */
/* areaauth    The sha'ed password that gives access to the area            */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_NV_ReadValueAuth(uint32_t nvIndex,
                              uint32_t offset,
                              uint32_t datasize,
                              unsigned char * buffer, uint32_t * buffersize,
                              unsigned char * areaauth   // key for area
                              ) 
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_NV_ReadValueAuth);
	uint32_t ret;
	uint32_t len;
	uint32_t datasize_no= htonl(datasize);
	uint32_t nvIndex_no = htonl(nvIndex);
	uint32_t offset_no  = htonl(offset);
	session sess;
	 

	/* check input arguments */
	if (buffer == NULL || areaauth == NULL) return ERR_NULL_ARG;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) return ERR_CRYPT_ERR;
	/* Open OIAP Session */
	ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      areaauth, TPM_ET_NV, nvIndex);
	if (ret != 0) 
		return ret;
	/* move Network byte order data to variable for hmac calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE, &ordinal_no,
	                   TPM_U32_SIZE, &nvIndex_no,
	                   TPM_U32_SIZE, &offset_no,
	                   TPM_U32_SIZE, &datasize_no,
	                   0,0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l l l L % o %", &tpmdata,
	                             ordinal_no,
	                               nvIndex_no,
	                                 offset_no,
	                                   datasize_no,
	                                     TSS_Session_GetHandle(&sess),
	                                       TPM_NONCE_SIZE,nonceodd,
	                                         c,
	                                           TPM_HASH_SIZE,authdata);

	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata,"NV_ReadValueAuth");

	TSS_SessionClose(&sess);
	if (0 != ret) {
		return ret;
	}
	
	ret= tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &len);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     TPM_U32_SIZE + len, TPM_DATA_OFFSET,
	                     0,0);
	
	if (0 != ret) {
		return ret;
	}

	*buffersize = MIN(*buffersize, len);
	memcpy(buffer, &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE], *buffersize);
	return ret;
}

