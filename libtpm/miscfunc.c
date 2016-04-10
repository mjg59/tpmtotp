/********************************************************************************/
/*										*/
/*			     	TPM Misc Command Functions			*/
/*			     Written by J. Kravitz				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: miscfunc.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <tpmutil.h>
#include <oiaposap.h>
#include <tpmfunc.h>
#include <hmac.h>
#include "tpm.h"
#include "tpm_constants.h"
#include "tpm_error.h"
#include "tpmutil.h"

#define TPM_OWNER_ETYPE 0x0002
#define TPM_OWNER_EVALUE 0x40000001

/****************************************************************************/
/*                                                                          */
/*  GetCapabilityOwner                                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_GetCapabilityOwner(unsigned char *ownpass, uint32_t *volflags, uint32_t *nvolflags)
{
	uint32_t ret;
	STACK_TPM_BUFFER(tpmdata)
	/* data to be inserted into Request Buffer (in Network Byte Order) */
	/* the uint32_t and uint16_t values are stored in network byte order so they
	** are in the correct format when being hashed by the HMAC calculation */
	uint32_t command;                                 /* command ordinal */
	unsigned char nonceodd[TPM_HASH_SIZE];           /* odd nonce */
	unsigned char authdata[TPM_HASH_SIZE];           /* auth data */
	session sess;

	/* check that parameters are valid */
	if (ownpass == NULL || 
	    volflags == NULL || 
	    nvolflags == NULL) 
		return ERR_NULL_ARG;
	/* set up command and protocol values for TakeOwnership function */
	command =  htonl(TPM_ORD_GetCapabilityOwner);
	/* generate the odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (ret == 0) 
		return ret;
	/* initiate the OSAP protocol */
	ret = TSS_SessionOpen(SESSION_OSAP,&sess,ownpass,TPM_OWNER_ETYPE,TPM_OWNER_EVALUE);
	if (ret != 0) 
		return ret;
	/* calculate the Authorization Data */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,0,
	                   TPM_U32_SIZE,&command,
	                   0,0);
	if (ret != 0)
	{
		TSS_SessionClose(&sess);
		return ret;
	}
	/* insert all the calculated fields into the request buffer */
	ret = TSS_buildbuff("00 c2 T l L % 00 %",&tpmdata,
	                             command,
	                               TSS_Session_GetHandle(&sess),
	                                 TPM_HASH_SIZE, nonceodd,
	                                     TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"GetCapabilityOwner");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		return ret;
	}
	ret = TSS_checkhmac1(&tpmdata,command,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     TPM_U32_SIZE,TPM_DATA_OFFSET,
	                     TPM_U32_SIZE,TPM_DATA_OFFSET + TPM_U32_SIZE,
	                     TPM_U32_SIZE,TPM_DATA_OFFSET + TPM_U32_SIZE + TPM_U32_SIZE,
	                     0,0);
	if (ret != 0) {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET+4,nvolflags);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret  = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET+4+TPM_U32_SIZE, volflags);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	return 0;
}

 
/****************************************************************************/
/*                                                                          */
/*  GetCapability                                                           */
/*                                                                          */
/****************************************************************************/
static uint32_t TPM_GetCapability_Internal(uint32_t caparea, 
                                           struct tpm_buffer *scap,
                                           struct tpm_buffer *response,
                                           int allowTransport)
{
	uint32_t ret;
	uint32_t rlen;
	uint32_t ordinal_no = htonl(TPM_ORD_GetCapability);
	STACK_TPM_BUFFER(tpmdata)       /* request/response buffer */
	uint32_t scaplen = 0;
	unsigned char *buffer = NULL;

	/* check arguments */
	if (scap) {
		scaplen = scap->used;
		buffer = scap->buffer;
	}
	if (response == NULL)
		return ERR_NULL_ARG;

	ret = TSS_buildbuff("00 c1 T l L @",&tpmdata,
	                             ordinal_no,  
	                               caparea,
	                                 scaplen,buffer);
	if ((ret & ERR_MASK) != 0) 
		return ret;

	/* transmit the request buffer to the TPM device and read the reply */
	if (allowTransport)
	        ret = TPM_Transmit(&tpmdata,"GetCapability");
        else
                ret = TPM_Transmit_NoTransport(&tpmdata, "GetCapability");
	if (ret != 0) 
		return ret;
	ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &rlen);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	if (NULL != response) {
		SET_TPM_BUFFER(response, 
		               &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
		               rlen);
	}
	return 0;
}

uint32_t TPM_GetCapability(uint32_t caparea, 
                           struct tpm_buffer *scap,
                           struct tpm_buffer *response)
{
        return TPM_GetCapability_Internal(caparea, scap, response, 1);
}

uint32_t TPM_GetCapability_NoTransport(uint32_t caparea, 
                                       struct tpm_buffer *scap,
                                       struct tpm_buffer *response)
{
        return TPM_GetCapability_Internal(caparea, scap, response, 0);
}



/****************************************************************************/
/*                                                                          */
/*  GetCapabilitySigned                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_GetCapabilitySigned(uint32_t keyhandle,
                                 unsigned char * keypass,
                                 unsigned char * antiReplay,
                                 uint32_t caparea, 
                                 struct tpm_buffer *scap, 
                                 struct tpm_buffer *resp,
                                 unsigned char *sig , uint32_t *siglen)
{
	uint32_t ret;
	uint32_t rlen;
	STACK_TPM_BUFFER(tpmdata)       /* request/response buffer */
	uint32_t ordinal_no = htonl(TPM_ORD_GetCapabilitySigned);
	uint32_t keyhandle_no = htonl(keyhandle);
	uint32_t caparea_no = htonl(caparea);
	unsigned char c = 0;
	unsigned char authdata[TPM_HASH_SIZE];
	uint32_t ssize;
	unsigned char *buffer = NULL;
	uint32_t subcaplen = 0;
	uint32_t subcaplen_no;

	/* check arguments */
	if (scap) {
		subcaplen = scap->used;
		buffer = scap->buffer;
	}
	subcaplen_no = htonl(subcaplen);
	
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}
	
	if (resp == NULL) return ERR_NULL_ARG;

	if (NULL != keypass) {
		unsigned char nonceodd[TPM_HASH_SIZE];
		session sess;

		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) 
			return ERR_CRYPT_ERR;

		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
		                      &sess,
		                      keypass, TPM_ET_KEYHANDLE,keyhandle);
		if (0 != ret) {
			return ret;
		}

		/* move Network byte order data to variable for hmac calculation */
		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_NONCE_SIZE, antiReplay,
		                   TPM_U32_SIZE, &caparea_no,
		                   TPM_U32_SIZE, &subcaplen_no,
		                   subcaplen   , buffer,
		                   0,0);
		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}

		ret = TSS_buildbuff("00 c2 T l l % l @ L % o %",&tpmdata,
		                             ordinal_no,
		                               keyhandle_no,
		                                 TPM_NONCE_SIZE, antiReplay,
		                                   caparea_no,
		                                     subcaplen,buffer,
		                                       TSS_Session_GetHandle(&sess),
		                                         TPM_NONCE_SIZE, nonceodd,
		                                           c,
		                                             TPM_HASH_SIZE, authdata);

		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"GetCapability - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) 
			return ret;

		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET+TPM_U32_SIZE, &rlen);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_U32_SIZE+rlen, &ssize);
		if ((ret & ERR_MASK)) {
			return ret;
		}

		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     TPM_U32_SIZE+TPM_U32_SIZE+rlen+TPM_U32_SIZE+ssize, TPM_DATA_OFFSET,
		                     0,0);
		if (ret != 0)
			return ret;
	} else {
		ret = TSS_buildbuff("00 c1 T l l % l @",&tpmdata,
		                             ordinal_no,
		                               keyhandle_no,
		                                 TPM_NONCE_SIZE, antiReplay,
		                                   caparea_no,
		                                     subcaplen,buffer);

		if ((ret & ERR_MASK) != 0) {
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"GetCapability - NO AUTH");
		if (ret != 0) 
			return ret;

		ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET+TPM_U32_SIZE, &rlen);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_U32_SIZE+rlen, &ssize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
	}
	if (NULL != resp) {
		SET_TPM_BUFFER(resp,
		               &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_U32_SIZE],
		               rlen);
	}

	if (NULL != sig ) {
		*siglen = MIN(*siglen, ssize);
		memcpy(sig, 
		       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_U32_SIZE+rlen+TPM_U32_SIZE], 
		       *siglen);
	}

	return ret;
}


/****************************************************************************/
/*                                                                          */
/*  SetCapability                                                           */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_SetCapability(uint32_t caparea, 
                           unsigned char *subcap  , uint32_t subcaplen, 
                           struct tpm_buffer *setValue,
                           unsigned char * operatorauth)
{
	STACK_TPM_BUFFER(tpmdata)
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_SetCapability);
	uint32_t caparea_no = htonl(caparea);
	uint32_t ret;
	
	/* check input arguments */


	if (NULL != operatorauth) {
		unsigned char nonceodd[TPM_NONCE_SIZE];
		unsigned char authdata[TPM_NONCE_SIZE];
		session sess;
		uint32_t subcaplen_no = htonl(subcaplen);
		uint32_t setValueSize_no = htonl(setValue->used);
		
		/* generate odd nonce */
		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) 
			return ERR_CRYPT_ERR;

		/* Open OIAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP,
		                      &sess,
		                      operatorauth, TPM_ET_OWNER, 0);
		                      
		if (ret != 0) 
			return ret;

		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE, &ordinal_no,
		                   TPM_U32_SIZE, &caparea_no,
		                   TPM_U32_SIZE, &subcaplen_no,
		                   subcaplen   , subcap,
		                   TPM_U32_SIZE, &setValueSize_no,
		                   setValue->used, setValue->buffer,
		                   0,0);

		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l @ @ L % o %", &tpmdata,
		                             ordinal_no,
		                               caparea_no,
		                                 subcaplen, subcap,
		                                   setValue->used, setValue->buffer,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_NONCE_SIZE, nonceodd,
		                                         c,
		                                           TPM_HASH_SIZE, authdata);
		if ( (ret  & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"SetCapability - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		/* check the HMAC in the response */
		
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     0,0);
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l @ @", &tpmdata,
		                             ordinal_no,
		                               caparea_no,
		                                 subcaplen, subcap,
		                                   setValue->used, setValue->buffer);

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"SetCapability");
	}
	return ret;
}

/****************************************************************************/
/*                                                                          */
/*  Reset TPM                                                               */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Reset()
{
	STACK_TPM_BUFFER(tpmdata)
	TSS_buildbuff("00 c1 00 00 00 0a 00 00 00 5a",&tpmdata);
	return TPM_Transmit(&tpmdata,"Reset");
}
   
/****************************************************************************/
/*                                                                          */
/*  Convert Error code to message                                           */
/*                                                                          */
/****************************************************************************/
static char *msgs[] = {
   "Unknown error"                                      ,
   "Authentication failed (Incorrect Password)"         ,
   "Illegal index"                                      ,
   "Bad parameter"                                      ,
   "Auditing failure"                                   ,
   "Clear disabled"                                     ,
   "TPM deactivated"                                    ,
   "TPM disabled"                                       ,
   "Target command disabled"                            ,
   "Operation failed"                                   ,
   "Ordinal unknown"                                    ,
   "Owner installation disabled"                        ,
   "Invalid key handle"                                 ,
   "Target key not found"                               ,
   "Unacceptable encryption scheme"                     ,
   "Migration authorization failed"                     ,
   "PCR information incorrect"                          ,
   "No room to load key"                                ,
   "No SRK set"                                         ,
   "Encrypted blob invalid"                             ,
   "TPM already has owner"                              ,
   "TPM out of resources"                               ,
   "Random string too short"                            ,
   "TPM out of space"                                   ,
   "PCR mismatch"                                       ,
   "Paramsize mismatch"                                 ,
   "No existing SHA-1 thread"                           ,
   "SHA-1 thread error"                                 ,
   "TPM self test failed - TPM shutdown"                ,
   "Authorization failure for 2nd key"                  ,
   "Invalid tag value"                                  ,
   "TPM I/O error"                                      ,
   "Encryption error"                                   ,
   "Decryption failure"                                 ,
   "Invalid handle"                                     ,
   "TPM has no endorsement key"                         ,
   "Invalid key usage"                                  ,
   "Invalid entity type"                                ,
   "Incorrect command sequence"                         ,
   "Inappropriate signature data"                       ,
   "Unsupported key properties"                         ,
   "Incorrect migration properties"                     ,
   "Incorrect signature or encryption scheme"           ,
   "Incorrect data size"                                ,
   "Incorrect mode parameter"                           ,
   "Invalid presence values"                            ,
   "Incorrect version"                                  ,
   "No support for wrapped transports"                  ,
   "Audit construction failed, command unsuccessful"    ,
   "Audit construction failed, command successful"      ,
   "Not resetable"                                      ,
   "Missing locality information"                       ,
   "Incorrect type"                                     ,
   "Invalid resource"                                   ,
   "Not in FIPS mode"                                   ,
   "Invalid family"                                     ,
   "No NV permission"                                   ,
   "Requires signed command"                            ,
   "Key not supported"                                  ,
   "Authentication conflict"                            ,
   "NV area is locked"                                  ,
   "Bad locality"                                       ,
   "NV area is read-only"                               ,
   "No protection on write into NV area"                ,
   "Family count value does not match"                  ,
   "NV area is write locked"                            ,
   "Bad NV area attributes"                             ,
   "Invalid structure"                                  ,
   "Key under control by owner"                         ,
   "Bad counter handle"                                 ,
   "Not full write"                                     ,
   "Context GAP"                                        ,
   "Exceeded max NV writes without owner"               ,
   "No operator authorization value set"                ,
   "Resource missing"                                    ,
   "Delegate administration is locked"                  ,
   "Wrong delegate family"                              ,
   "Delegation management not enabled"                  ,
   "Command executed outside transport session"         ,
   "Key is under control of owner"                      ,
   "No DAA resources available"                         ,
   "InputData0 is inconsistent"                         ,
   "InputData1 is inconsistent"                         ,
   "DAA: Issuer settings are not consistent"            ,
   "DAA: TPM settings are not consistent"               ,
   "DAA stage failure"                                  ,
   "DAA: Issuer validity check detected inconsistency"  ,
   "DAA: Wrong 'w'"                                     ,
   "Bad handle"                                         ,
   "No room for context"                                ,
   "Bad context"                                        ,
   "Too many contexts"                                  ,
   "Migration authority signature failure"              ,
   "Migration destination not authenticated"            ,
   "Migration source incorrect"                         ,
   "Migration authority incorrect"			,
   "No error description"				,
   "Attempt to revoke the EK and the EK is not revocable",
   "Bad signature of CMK ticket"			,
   "There is no room in the context list for additional contexts",
   };

static char *msgs_nonfatal[] = {
    "Retry"						,
    "Needs self test"					,
    "Doing self test"					,
    "Defend lock running"
};

static char *msgs2[] = {
   "HMAC authorization verification failed"             ,
   "NULL argument"                                      ,
   "Invalid argument"                                   ,
   "Error from OpenSSL library"                         ,
   "I/O error"                                          ,
   "Memory allocation error"                            ,
   "File error"                                         ,
   "Data in stream are bad"                             ,
   "Too many data"                                      ,
   "Buffer too small"                                   ,
   "Incorrect structure type"                           ,
   "Searched item could not be found"                   ,
   "Environment variable not set"                       ,
   "No transport allowed for this ordinal"              ,
   "Bad tag in response message"                        ,
   "Incorrect signature"                                ,
   "PCR value list does not correspond to IMA value list",
   "Checksum verification failed"                       ,
   "Format error in TPM response"                       ,
   "Choice of session type is bad"                      ,
   "Failure during close()/fclose()"                    ,
   "File write error"                                   ,
   "File read error"                                    ,
   };
   
char *TPM_GetErrMsg(uint32_t code)
   {
   if (code  >= ERR_HMAC_FAIL &&
       code  <  ERR_LAST) {
       return msgs2[code - ERR_HMAC_FAIL];
   }

   if ((code > 0) && (code < 100)) {
       return msgs[code];
   }
   if ((code >= TPM_NON_FATAL) &&
       (code < (TPM_NON_FATAL + 4))) {
       if ((code & 0xff) == 0) {
	   printf("\n\n\nRETRY error code\n\n\n");
       }
       return msgs_nonfatal[code - TPM_NON_FATAL];
   }
   return msgs[0];
   }

/*
 * Allocate a TPM buffer that can be used to communicate
 * with the TPM. It will be of the size that the TPM
 * supports.
 */
struct tpm_buffer *TSS_AllocTPMBuffer(int len)
{
	struct tpm_buffer * buf = NULL;
	STACK_TPM_BUFFER(scap)
	STORE32(scap.buffer, 0, TPM_CAP_PROP_INPUT_BUFFER);
	scap.used = 4;
	
	if (len <= 0) {
		STACK_TPM_BUFFER(response)
		static int buf_len = -1;
		if (buf_len == -1) {
			uint32_t ret = -1;
			/* MUST check if GetCapability is audited... */
			_TPM_IsAuditedOrdinal(TPM_ORD_GetCapability,&ret);
			if (0 == ret) {
				/* Only do this once through usage of the static var. */
				ret = TPM_GetCapability(TPM_CAP_PROPERTY,
				                        &scap,
				                        &response);
			}
			if ( 0 != ret ) {
				buf_len = 2 * 1024;
			} else {
				buf_len = LOAD32(response.buffer, 0);
			}
		} else {
			len = buf_len;
		}
	}
	if (len > 16 * 1024) {
		len = 16 * 1024;
	} else if (len < 1024) {
		len = 2 * 1024;
	}
	buf = (struct tpm_buffer *)malloc((size_t)&buf->buffer[len]);
	if (NULL != buf) {
		buf->size = len;
		buf->used = 0;
	}
	return buf;
}

void TSS_FreeTPMBuffer(struct tpm_buffer * buf)
{
	free(buf);
}


uint32_t TSS_SetTPMBuffer(struct tpm_buffer *tb,
                          const unsigned char *buffer,
                          uint32_t buflen)
{
	uint32_t len = MIN(buflen, tb->size);
	memcpy(tb->buffer, buffer, len);
	tb->used = len;
	return len;
}

uint32_t TPM_GetNumPCRRegisters(uint32_t *res)
{
	uint32_t ret;
	uint32_t caparea = TPM_CAP_PROPERTY;
	STACK_TPM_BUFFER(resp);
	STACK_TPM_BUFFER(scap);
	uint32_t subprop = TPM_CAP_PROP_PCR;
	
	ret = TSS_buildbuff("L", &scap,
	                     subprop);
	if (ret & ERR_MASK) {
		return ret;
	}
	ret = TPM_GetCapability(caparea, &scap, &resp);
	if (ret != 0) {
		return ret;
	}

	ret = TSS_parsebuff("L", &resp, 0, res);
	if (ret & ERR_MASK)
		return ret;

	return 0;
}

uint32_t TPM_GetTPMInputBufferSize(uint32_t *size)
{
	uint32_t ret;
	STACK_TPM_BUFFER(scap)
	STACK_TPM_BUFFER(response)
	STORE32(scap.buffer, 0, TPM_CAP_PROP_INPUT_BUFFER);
	scap.used = 4;
	
	ret = TPM_GetCapability(TPM_CAP_PROPERTY,
	                        &scap,
	                        &response);
	if ( 0 != ret ) {
		*size = 2 * 1024;
	} else {
		*size = LOAD32(response.buffer, 0);
	}
	return ret;
}
