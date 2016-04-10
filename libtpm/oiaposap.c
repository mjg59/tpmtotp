/********************************************************************************/
/*										*/
/*			     	TPM OAIP/OSAP protocols				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/* 		$Id: oiaposap.c 4702 2013-01-03 21:26:29Z kgoldman $       	*/
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
#include <tpm_constants.h>
#include <tpm_structures.h>
#include <tpm_error.h>
#include "tpmfunc.h"
#include <hmac.h>
#include <oiaposap.h>

#include <openssl/aes.h>

void TPM_DetermineSessionEncryption(const session *sess, int *use_xor)
{
	const osapsess *osap = &sess->type.osap;
	const dsapsess *dsap = &sess->type.dsap;
	*use_xor = 1;
	if ((sess->sess_type == SESSION_OSAP && 
	     (osap->etype >> 8) == TPM_ET_AES128_CTR) ||
	    (sess->sess_type == SESSION_DSAP &&
	     (dsap->etype >> 8) == TPM_ET_AES128_CTR)) {
		*use_xor = 0;
	}
}

void TPM_CreateEncAuth(const session *sess, const unsigned char *in, unsigned char *out,
                       const unsigned char *nonceodd)
{
	int use_xor = 0;
	TPM_DetermineSessionEncryption(sess, &use_xor);
	if (!use_xor) {
		AES_KEY aeskey;
		/*
		 * use AES
		 */
		int rc;
		unsigned char ctr[TPM_AES_BLOCK_SIZE];

		rc = AES_set_encrypt_key(TSS_Session_GetAuth((session *)sess),
		                         TPM_AES_BITS,
		                         &aeskey);
                (void)rc;
		if (!nonceodd) {
			memcpy(ctr,
			       TSS_Session_GetENonce((session *)sess),
			       sizeof(ctr));
		} else {
			memcpy(ctr,
			       nonceodd,
			       sizeof(ctr));
		}

		TPM_AES_ctr128_Encrypt(out,
				       in,
				       TPM_HASH_SIZE,
				       &aeskey,
				       ctr);
	} else {
		uint32_t i;
		unsigned char xorwork[TPM_HASH_SIZE * 2];
		unsigned char xorhash[TPM_HASH_SIZE];
		/* calculate encrypted authorization value for new key */
		memcpy(xorwork,
		       TSS_Session_GetAuth((session *)sess),
		       TPM_HASH_SIZE);
		if (!nonceodd) {
			memcpy(xorwork+TPM_HASH_SIZE,
			       TSS_Session_GetENonce((session *)sess),
			       TPM_HASH_SIZE);
		} else {
			memcpy(xorwork+TPM_HASH_SIZE,
			       nonceodd,
			       TPM_HASH_SIZE);
		}
		TSS_sha1(xorwork,TPM_HASH_SIZE * 2,xorhash);
		for (i = 0; i < TPM_HASH_SIZE; i++) 
			out[i] = xorhash[i] ^ in[i];
	}
}

/****************************************************************************/
/*                                                                          */
/* Open an OIAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OIAPopen(uint32_t *handle, unsigned char *enonce)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ret;

	/* check input arguments */
	if (handle == NULL || enonce == NULL) 
		return ERR_NULL_ARG;
	/* build request buffer */
	ret = TSS_buildbuff("00 C1 T 00 00 00 0A",&tpmdata);
	if ((ret & ERR_MASK) != 0) 
		return ret;
	/* transmit request to TPM and get result */
	ret = TPM_Transmit(&tpmdata,"OIAP");
	if (ret != 0) 
		return ret;
	ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, handle);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	memcpy(enonce,
	       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE],
	       TPM_NONCE_SIZE);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Close an OIAP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OIAPclose(uint32_t handle)
{
	return TSS_HANDclose(handle, TPM_RT_AUTH);
}
   
/****************************************************************************/
/*                                                                          */
/* Open an OSAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OSAPopen(osapsess *sess, const unsigned char *key, uint16_t etype, uint32_t evalue)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ret;
	const char *et_aes = getenv("TPM_ET_ENCRYPT_AES");
	if (et_aes && !strcmp("1",et_aes)) {
		etype |= (TPM_ET_AES128_CTR << 8);
	}

	/* check input arguments */
	if (key == NULL || sess == NULL) 
		return ERR_NULL_ARG;
	TSS_gennonce(sess->ononceOSAP);
	ret = TSS_buildbuff("00 C1 T 00 00 00 0B S L %",&tpmdata, 
	                                         etype, 
	                                           evalue, 
	                                             TPM_NONCE_SIZE, sess->ononceOSAP);
	if ((ret & ERR_MASK) != 0) return ret;
	ret = TPM_Transmit(&tpmdata,"OSAP");
	if (ret != 0)  {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &sess->handle);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	sess->etype = etype;
	memcpy(sess->enonce,&(tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE]),TPM_NONCE_SIZE);
	memcpy(sess->enonceOSAP,&(tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_NONCE_SIZE]),TPM_NONCE_SIZE);
	ret = TSS_rawhmac(sess->ssecret, key, TPM_HASH_SIZE,
	                  TPM_NONCE_SIZE, sess->enonceOSAP,
	                  TPM_NONCE_SIZE, sess->ononceOSAP,
	                  0,0);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Close an OSAP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OSAPclose(osapsess *sess)
{
	uint32_t ret;

	if (sess == NULL)
		return ERR_NULL_ARG;
	ret = TSS_HANDclose(sess->handle, TPM_RT_AUTH);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Open a DSAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_DSAPopen(dsapsess *sess,
                      unsigned char *key,
                      uint16_t etype,
                      uint32_t keyhandle,
                      unsigned char *evalue, uint32_t evalueSize)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ret = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_DSAP);
	const char *et_aes = getenv("TPM_ET_ENCRYPT_AES");
	if (et_aes && !strcmp("1",et_aes)) {
		etype |= (TPM_ET_AES128_CTR << 8);
	}

	/* check input arguments */
	if (key == NULL || sess == NULL)
		return ERR_NULL_ARG;

	TSS_gennonce(sess->ononceDSAP);
	ret = TSS_buildbuff("00 C1 T l S L % @",&tpmdata,
	                             ordinal_no,
	                               etype,
	                                 keyhandle,
	                                   TPM_NONCE_SIZE, sess->ononceDSAP,
	                                     evalueSize, evalue);
	if ((ret & ERR_MASK) != 0)
		return ret;
	ret = TPM_Transmit(&tpmdata,"DSAP");
	if (ret != 0)
		return ret;
	ret = tpm_buffer_load32(&tpmdata,TPM_DATA_OFFSET, &sess->handle);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	sess->etype = etype;
	memcpy(sess->enonce,
	       &(tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE]),
	       TPM_NONCE_SIZE);
	memcpy(sess->enonceDSAP,
	       &(tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_NONCE_SIZE]),
	       TPM_NONCE_SIZE);

	ret = TSS_rawhmac(sess->ssecret, key, TPM_HASH_SIZE,
	                  TPM_NONCE_SIZE, sess->enonceDSAP,
	                  TPM_NONCE_SIZE, sess->ononceDSAP,
	                  0,0);

	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Close a DSAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_DSAPclose(dsapsess *sess)
{
	uint32_t ret;

	if (sess == NULL) 
		return ERR_NULL_ARG;

	ret = TSS_HANDclose(sess->handle, TPM_RT_AUTH);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Terminate the Handle Opened by TPM_OIAPOpen, or TPM_OSAPOpen             */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_HANDclose(uint32_t handle, TPM_RESOURCE_TYPE rt)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ret;
	uint32_t handle_no = htonl(handle);
	char *version = getenv("TPM_VERSION");
	
	if (version == NULL || !strcmp("11",version)) {
		ret = TSS_buildbuff("00 C1 T 00 00 00 96 l",&tpmdata,
	                                         handle_no);
		if ((ret & ERR_MASK) != 0) return ret;
		ret = TPM_Transmit(&tpmdata,"Terminate Handle");
		if (ret == TPM_BAD_ORDINAL) {
			ret = TPM_FlushSpecific(handle, rt);
		}
	} else {
			ret = TPM_FlushSpecific(handle, rt);
	}
	return ret;
}


uint32_t TSS_Session_CreateTransport(session *sess,
                                     unsigned char *transAuth,
                                     uint32_t transHandle,
                                     unsigned char *transNonce)
{
	sess->sess_type = SESSION_TRAN;
	memcpy(sess->authdata, transAuth, TPM_AUTHDATA_SIZE);
	sess->type.tran.handle = transHandle;
	TSS_Session_SetENonce(sess,transNonce);
	return 0;
}

uint32_t TSS_SessionOpen(uint32_t allowed_type,
                         session * sess,
                         unsigned char *passHash, uint16_t etype, uint32_t evalue)
{
	char * sess_str = getenv("TPM_SESSION");
	uint32_t want = SESSION_OIAP;
	uint32_t have = SESSION_OIAP;

	memcpy(sess->authdata, passHash, TPM_AUTHDATA_SIZE);

	if (etype == TPM_ET_KEY || etype == TPM_ET_KEYHANDLE) {
		needKeysRoom(evalue, 0,0, -1);
	}

	if (NULL == passHash) {
		allowed_type &= SESSION_OIAP;
		if (0 == allowed_type) {
			printf("Bad allowed type! Need to be able to use OIAP session.\n");
			return ERR_BAD_ARG;
		}
		have = allowed_type;
	} else {
		if (NULL != sess_str) {
			if (0 == strcasecmp("dsap",sess_str)) {
				want = SESSION_DSAP;
			} else if (0 == strcasecmp("osap",sess_str)) {
				want = SESSION_OSAP;
			} else if (0 == strcasecmp("oiap",sess_str)) {
				want = SESSION_OIAP;
			}
		}
		have = want & allowed_type;

		if (0 == have) {
			have = (allowed_type & ~SESSION_DSAP);
		}
	}

	if (have & SESSION_DSAP) {
		uint32_t ret;
		uint32_t keyhandle = 0;
		unsigned char dsapEvalue[sizeof(TPM_DELEGATE_OWNER_BLOB) +
		                         sizeof(TPM_DELEGATE_KEY_BLOB) + 
		                         1000];
		uint32_t dsapEvalueSize = sizeof(dsapEvalue);
		sess->sess_type = SESSION_DSAP;
		
		if (TPM_ET_KEYHANDLE    == etype ||
		    TPM_ET_SRK          == etype ||
		    TPM_ET_DEL_KEY_BLOB == etype) {
			keyhandle = evalue;     // assumed to be a keyhandle
			etype = TPM_ET_DEL_KEY_BLOB;
			ret = TPM_GetDelegationBlob(TPM_ET_DEL_KEY_BLOB,
			                            keyhandle,
			                            passHash,
			                            dsapEvalue, &dsapEvalueSize);
			if (ret != 0) {
				// if it was not found, it could be that DSAP is not
				// really used, but OSAP or OIAP will do the trick.
				// Try those instead then!!!
				goto try_other;
			}
		} else
		if (TPM_ET_OWNER          == etype  ||
		    TPM_ET_DEL_OWNER_BLOB == etype) {
			etype = TPM_ET_DEL_OWNER_BLOB;
			ret = TPM_GetDelegationBlob(TPM_ET_DEL_OWNER_BLOB,
			                            0,
			                            passHash,
			                            dsapEvalue, &dsapEvalueSize);
			if (ret != 0) {
				// if it was not found, it could be that DSAP is not
				// really used, but OSAP or OIAP will do the trick.
				// Try those instead then!!!
				goto try_other;
			}
		} else
		if (TPM_ET_DEL_ROW == etype) {
			/* this is really weird. No real authorization info
			   ... */
			TPM_DELEGATE_INDEX evalue_no = ntohl(evalue);
			dsapEvalueSize = sizeof(evalue_no);
			memcpy(dsapEvalue,
			       &evalue_no,
			       sizeof(evalue_no));
		} else {
			// I don't support anything else at the moment...
			return TPM_BAD_MODE;
		}
		return TSS_DSAPopen(&sess->type.dsap,
		                    passHash,
		                    etype,
		                    keyhandle,
		                    dsapEvalue, dsapEvalueSize
		                    );
	}
try_other:
	if (have & SESSION_OSAP) {
		/*
		 * Open an OSAP session
		 */
		sess->sess_type = SESSION_OSAP;
		return TSS_OSAPopen(&sess->type.osap,
		                    passHash,
		                    etype,
		                    evalue);
	} else {
#if 0
		Not doing this since this prevents ligitimate OIAP
		sessions to be established since those cannot be replaced
		with a DSAP session. key delegation with sealing and
		unsealing surfaced this as an error.
		/* if DSAP is wanted and OSAP is not specified, leave here */
		if ((want & SESSION_DSAP) && !(want & SESSION_OIAP)) {
			return ERR_BAD_SESSION_TYPE;
		}
#endif
		/*
		 * Open an OIAP session
		 */
		sess->sess_type = SESSION_OIAP;
		return TSS_OIAPopen(&sess->type.oiap.handle,
		                     sess->type.oiap.enonce);
	}

	return ERR_BAD_SESSION_TYPE;
}

uint32_t TSS_SessionClose(session * sess)
{
	switch (sess->sess_type) {
		case SESSION_OIAP:
			return TSS_OIAPclose(sess->type.oiap.handle);
		break;
		
		case SESSION_OSAP:
			return TSS_OSAPclose(&sess->type.osap);
		break;
		
		case SESSION_DSAP:
			return TSS_DSAPclose(&sess->type.dsap);
		break;
		
		case SESSION_TRAN:
			printf("%s for Transport not implemented.\n",
			       __FUNCTION__);
		break;
	}
	
	return ERR_BAD_ARG;
}

unsigned char * TSS_Session_GetAuth(session * sess)
{
	switch (sess->sess_type) {
		case SESSION_OIAP:
		case SESSION_TRAN:
			return sess->authdata;
		break;
		
		case SESSION_OSAP:
			return sess->type.osap.ssecret;
		break;
		
		case SESSION_DSAP:
			return sess->type.dsap.ssecret;
		break;
	}
	return NULL;
}

unsigned char * TSS_Session_GetENonce(session * sess)
{
	switch (sess->sess_type) {
		case SESSION_OIAP:
			return sess->type.oiap.enonce;
		break;
		
		case SESSION_OSAP:
			return sess->type.osap.enonce;
		break;
		
		case SESSION_DSAP:
			return sess->type.dsap.enonce;
		break;
		
		case SESSION_TRAN:
			return sess->type.tran.enonce;
		break;
	}
	return NULL;
}

void TSS_Session_SetENonce(session * sess, const unsigned char *enonce)
{
	unsigned char *ptr = NULL;
	switch (sess->sess_type) {
		case SESSION_OIAP:
			ptr = sess->type.oiap.enonce;
		break;
		
		case SESSION_OSAP:
			ptr = sess->type.osap.enonce;
		break;
		
		case SESSION_DSAP:
			ptr = sess->type.dsap.enonce;
		break;
		
		case SESSION_TRAN:
			ptr = sess->type.tran.enonce;
		break;
	}
	if (ptr) {
		memcpy(ptr, enonce, TPM_NONCE_SIZE);
	}
}

uint32_t TSS_Session_GetHandle(session * sess)
{
	switch (sess->sess_type) {
		case SESSION_OIAP:
			return sess->type.oiap.handle;
		break;
		
		case SESSION_OSAP:
			return sess->type.osap.handle;
		break;
		
		case SESSION_DSAP:
			return sess->type.dsap.handle;
		break;
		
		case SESSION_TRAN:
			return sess->type.tran.handle;
		break;
	}
	return ERR_BAD_ARG;
}

uint32_t TPM_SetOwnerPointer(uint16_t entityType, 
                             uint32_t entityValue)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_SetOwnerPointer);
	uint16_t entityType_no = htons(entityType);
	uint32_t entityValue_no = htonl(entityValue);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l s l",&tpmdata,
	                             ordinal_no,
	                               entityType_no,
	                                 entityValue_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"SetOwnerPointer");
	
	return ret;
}
