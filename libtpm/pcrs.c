/********************************************************************************/
/*										*/
/*			     	TPM PCR Processing Functions			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: pcrs.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <oiaposap.h>
#include <hmac.h>
#include <pcrs.h>
#include <tpm_constants.h>
#include <tpm_structures.h>
#include "tpmfunc.h"


uint32_t TPM_ValidateSignature(uint16_t sigscheme,
                               struct tpm_buffer *data,
                               struct tpm_buffer *signature,
                               RSA *rsa)
{
	STACK_TPM_BUFFER(tsi_ser);
	unsigned char sighash[TPM_HASH_SIZE];	/* hash of quote info structure */
	uint32_t ret = 0;
	unsigned char padded[4096];
	unsigned char plainarray[4096];
	int plain, irc;

	switch (sigscheme) {
		case TPM_SS_RSASSAPKCS1v15_INFO:
		case TPM_SS_RSASSAPKCS1v15_SHA1:
			/* create the hash of the quoteinfo structure for signature verification */
			TSS_sha1(data->buffer, data->used, sighash);
			/*
			 ** perform an RSA verification on the signature returned by Quote
			 */
			ret = RSA_verify(NID_sha1, sighash, sizeof(sighash),
			                 signature->buffer, signature->used,
			                 rsa);
			if (ret != 1) {
				ret =  ERR_SIGNATURE;
			} else {
				ret = 0;
			}
		break;
		case TPM_SS_RSASSAPKCS1v15_DER:
			/* create the hash of the quoteinfo structure for signature verification */
			TSS_sha1(data->buffer, data->used, sighash);

			plain = RSA_public_decrypt(signature->used,
			                           signature->buffer,
			                           plainarray,
			                           rsa, RSA_NO_PADDING);
			if (plain == -1) {
				ret = ERR_SIGNATURE;
			}
			if (ret == 0) {
				irc = RSA_padding_add_PKCS1_type_1(padded,plain,sighash,sizeof(sighash));
				if (irc != 1) {
					ret = ERR_SIGNATURE;
				}
			}
			if (ret == 0) {
				if (memcmp(padded, plainarray, plain) != 0) {
					ret = ERR_SIGNATURE;
				}
			}
		break;
		default:
			ret = ERR_SIGNATURE;
	}
	return ret;
}

/* 
 * Validate the signature over a PCR composite structure.
 * Returns '0' on success, an error code otherwise.
 */
uint32_t TPM_ValidatePCRCompositeSignature(TPM_PCR_COMPOSITE *tpc,
                                           unsigned char *antiReplay,
                                           pubkeydata *pk,
                                           struct tpm_buffer *signature,
                                           uint16_t sigscheme)
{
	uint32_t ret;
	RSA *rsa;			/* openssl RSA public key */
	TPM_QUOTE_INFO tqi;
	STACK_TPM_BUFFER (ser_tqi);
	STACK_TPM_BUFFER(response);
	STACK_TPM_BUFFER (ser_tpc);
	/*
	** Convert to an OpenSSL RSA public key
	*/
	rsa = TSS_convpubkey(pk);

	ret = TPM_GetCapability(TPM_CAP_VERSION, NULL,
	                        &response);
	if (ret != 0) {
		RSA_free(rsa);
		return ret;
	}

	memcpy(&(tqi.version), response.buffer, response.used);
	memcpy(&(tqi.fixed), "QUOT", 4);
	memcpy(&(tqi.externalData), antiReplay, TPM_NONCE_SIZE);
	ret = TPM_WritePCRComposite(&ser_tpc, tpc);
	if ((ret & ERR_MASK)) {
		RSA_free(rsa);
		return ret;
	}
	/* create the hash of the PCR_composite data for the quoteinfo structure */
	TSS_sha1(ser_tpc.buffer, ser_tpc.used, tqi.digestValue);

	ret = TPM_WriteQuoteInfo(&ser_tqi, &tqi);
	if ((ret & ERR_MASK)) {
		RSA_free(rsa);
		return ret;
	}
	
	ret = TPM_ValidateSignature(sigscheme,
	                            &ser_tqi,
	                            signature,
	                            rsa);
	RSA_free(rsa);
	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Extend a specified PCR register by adding a new measure                  */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* pcrIndex  is the index of the PCR register to extend                     */
/* event     is pointing to a buffer the size of TPM_HASH_SIZE (=20) that   */
/*           contains the (encrypted) information to extend the PCR with    */
/* outDigest is pointing to a buffer the size of TPM_HASH_SIZE (-20) that   */
/*           will contain the new value of the PCR register upon return     */
/*           (may be NULL)                                                  */
/****************************************************************************/
uint32_t TPM_Extend(uint32_t pcrIndex,
                    unsigned char * event,
                    unsigned char * outDigest) {
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_Extend);
	uint32_t pcrIndex_no = htonl(pcrIndex);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l l %",&tpmdata,
	                             ordinal_no,
	                               pcrIndex_no,
	                                 TPM_HASH_SIZE, event);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"Extend");
	
	if (0 != ret) {
		return ret;
	}
	
	if (NULL != outDigest) {
		memcpy(outDigest, 
		       &tpmdata.buffer[TPM_DATA_OFFSET], 
		       TPM_HASH_SIZE);
	}
	
	return ret;
}



/****************************************************************************/
/*                                                                          */
/* Quote the specified PCR registers                                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to sign the results              */
/* tps       selection of the PCRs to quote                                 */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it will be assumed that no password is required       */
/* data      is a pointer to a nonce                                        */
/* tpc       is a pointer to an area to receive a pcrcomposite structure    */
/* signature is a pointer to an area to receive the signature               */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Quote(uint32_t keyhandle,
                   unsigned char *keyauth,
                   unsigned char *externalData,
                   TPM_PCR_SELECTION *tps,
                   TPM_PCR_COMPOSITE *tpc,
                   struct tpm_buffer *signature)
{
	uint32_t ret;
	STACK_TPM_BUFFER( tpmdata )
	session sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal = htonl(TPM_ORD_Quote);
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t pcrselsize;
	uint32_t valuesize;
	uint32_t sigsize;
	uint32_t offset;
	STACK_TPM_BUFFER( serPcrSel );

	/* check input arguments */
	if (tpc == NULL || externalData == NULL || signature == NULL) return ERR_NULL_ARG;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	ret = TPM_WritePCRSelection(&serPcrSel, tps);

	if ((ret & ERR_MASK))
		return ret;

	if (keyauth != NULL)  /* authdata required */ {
		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,
		                      keyauth,TPM_ET_KEYHANDLE,keyhandle);
		if (ret != 0) return ret;
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* move Network byte order data to variables for hmac calculation */
		c = 0;
		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal,
		                   TPM_HASH_SIZE,externalData,
		                   serPcrSel.used,serPcrSel.buffer,
		                   0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C2 T l l % % L % o %",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 TPM_HASH_SIZE,externalData,
		                                   serPcrSel.used, serPcrSel.buffer,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_NONCE_SIZE,nonceodd,
		                                         c,
		                                          TPM_HASH_SIZE,pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		
		offset = TPM_DATA_OFFSET;
		/* calculate the size of the returned Blob */
		ret  =  tpm_buffer_load16(&tpmdata,offset,&pcrselsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U16_SIZE + pcrselsize;
		
		ret =  tpm_buffer_load32(&tpmdata,offset,&valuesize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE + valuesize;
		ret =  tpm_buffer_load32(&tpmdata,offset, &sigsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE;

		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     offset-TPM_DATA_OFFSET+sigsize,TPM_DATA_OFFSET,
		                     0,0);
		if (ret != 0) {
			return ret;
		}
		ret = TPM_ReadPCRComposite(&tpmdata,
		                           TPM_DATA_OFFSET,
		                           tpc);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* copy the returned blob to caller */
		SET_TPM_BUFFER(signature,
		               &tpmdata.buffer[offset],
		               sigsize);
	} else  /* no authdata required */ {
		/* build the request buffer */
		ret = TSS_buildbuff("00 C1 T l l % %",&tpmdata,
		                             ordinal,
		                               keyhndl,
		                                 TPM_HASH_SIZE,externalData,
		                                   serPcrSel.used,serPcrSel.buffer);
		if ((ret & ERR_MASK) != 0) return ret;
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote");
		if (ret != 0) return ret;
		/* calculate the size of the returned Blob */
		offset = TPM_DATA_OFFSET;
		ret =  tpm_buffer_load16(&tpmdata,offset, &pcrselsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U16_SIZE + pcrselsize;
		ret  =  tpm_buffer_load32(&tpmdata,offset, &valuesize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE + valuesize;

		ret =  tpm_buffer_load32(&tpmdata,offset, &sigsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE;
		
		/* copy the returned PCR composite to caller */
		ret = TPM_ReadPCRComposite(&tpmdata,
		                           TPM_DATA_OFFSET,
		                           tpc);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* copy the returned blob to caller */
		SET_TPM_BUFFER(signature,
		               &tpmdata.buffer[offset],
		               sigsize);
	}
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Quote the specified PCR registers  (2nd function)                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to sign the results              */
/* pcrmap    is a 32 bit integer containing a bit map of the PCR register   */
/*           numbers to be used when sealing. e.g 0x0000001 specifies       */
/*           PCR 0. 0x00000003 specifies PCR's 0 and 1, etc.                */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it will be assumed that no password is required       */
/* data      is a pointer to the data to be sealed  (20 bytes)              */
/* pcrcompos is a pointer to an area to receive a pcrcomposite structure    */
/* blob      is a pointer to an area to receive the signed data             */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the signed data                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Quote2(uint32_t keyhandle,
                    TPM_PCR_SELECTION * selection,
                    TPM_BOOL addVersion,
                    unsigned char *keyauth,
                    unsigned char *antiReplay,
                    TPM_PCR_INFO_SHORT * pcrinfo,
                    struct tpm_buffer *versionblob,
                    struct tpm_buffer *signature)
{
	uint32_t ret;
	uint32_t rc;
	STACK_TPM_BUFFER( tpmdata )
	session sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_Quote2);
	uint16_t pcrselsize;
	uint32_t verinfosize;
	uint32_t sigsize;
	uint32_t storedsize;
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t keytype;
	struct tpm_buffer * serPCRSelection;
	uint32_t serPCRSelectionSize;

	/* check input arguments */
	if (pcrinfo   == NULL ||
	    selection == NULL ||
	    antiReplay == NULL) return ERR_NULL_ARG;
	keytype = 0x0001;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	TSS_gennonce(antiReplay);

	serPCRSelection = TSS_AllocTPMBuffer(TPM_U16_SIZE +
	                                     selection->sizeOfSelect);
	if (NULL == serPCRSelection) {
		return ERR_MEM_ERR;
	}

	ret = TPM_WritePCRSelection(serPCRSelection, selection);
	if (( ret & ERR_MASK) != 0) {
		TSS_FreeTPMBuffer(serPCRSelection);
		return ret;
	}
	serPCRSelectionSize = ret;

	if (keyauth != NULL) {
		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,keyauth,keytype,keyhandle);
		if (ret != 0)  {
			TSS_FreeTPMBuffer(serPCRSelection);
			return ret;
		}
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* move Network byte order data to variables for hmac calculation */

		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal_no,
		                   TPM_HASH_SIZE,antiReplay,
		                   serPCRSelectionSize, serPCRSelection->buffer,
		                   sizeof(TPM_BOOL), &addVersion,
		                   0,0);
		if (ret != 0) {
			TSS_FreeTPMBuffer(serPCRSelection);
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C2 T l l % % o L % o %",&tpmdata,
		                             ordinal_no,
		                               keyhndl,
		                                 TPM_HASH_SIZE,antiReplay,
		                                   serPCRSelectionSize,serPCRSelection->buffer,
		                                     addVersion,
		                                       TSS_Session_GetHandle(&sess),
		                                         TPM_NONCE_SIZE,nonceodd,
		                                           c,
		                                             TPM_HASH_SIZE,pubauth);
		TSS_FreeTPMBuffer(serPCRSelection);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote2 - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 C1 T l l % % o",&tpmdata,
		                             ordinal_no,
		                               keyhndl,
		                                 TPM_HASH_SIZE,antiReplay,
		                                   serPCRSelectionSize,serPCRSelection->buffer,
		                                     addVersion);
		TSS_FreeTPMBuffer(serPCRSelection);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote2");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
	}
	/* calculate the size of the returned Blob */
        ret =  tpm_buffer_load16(&tpmdata,TPM_DATA_OFFSET, &pcrselsize);
        if ((ret & ERR_MASK)) {
        	return ret;
        }
        pcrselsize += TPM_U16_SIZE + 1 + TPM_HASH_SIZE;
	ret =  tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + pcrselsize, &verinfosize);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret  =  tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + pcrselsize + TPM_U32_SIZE + verinfosize, &sigsize);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	storedsize   = pcrselsize + TPM_U32_SIZE + verinfosize +
	                            TPM_U32_SIZE + sigsize;

	if (keyauth != NULL) {
		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     storedsize,TPM_DATA_OFFSET,
		                     0,0);
		if (ret != 0) {
			return ret;
		}
	}
	/* copy the returned PCR composite to caller */
	
	if (pcrselsize != (rc = 
	     TPM_ReadPCRInfoShort(&tpmdata, TPM_DATA_OFFSET,
	                          pcrinfo))) {
		if ((rc & ERR_MASK)) 
			return rc;
		return ERR_BUFFER;
	}
	
	if (NULL != versionblob) {
		SET_TPM_BUFFER(
		       versionblob,
		       &tpmdata.buffer[TPM_DATA_OFFSET+pcrselsize+TPM_U32_SIZE],
		       verinfosize);
	}
	
	if (NULL != signature) {
		SET_TPM_BUFFER(signature,
		       &tpmdata.buffer[TPM_DATA_OFFSET+pcrselsize+TPM_U32_SIZE+verinfosize+TPM_U32_SIZE],
		       sigsize);
	}

	return ret;
}
             

/****************************************************************************/
/*                                                                          */
/*  Read PCR value                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   
   if (pcrvalue == NULL) return ERR_NULL_ARG;
   ret = TSS_buildbuff("00 c1 T 00 00 00 15 L",&tpmdata,pcrindex);
   if ((ret & ERR_MASK) != 0 ) return ret;
   ret = TPM_Transmit(&tpmdata,"PCRRead");
   if (ret != 0) return ret;
   memcpy(pcrvalue,
          &tpmdata.buffer[TPM_DATA_OFFSET],
          TPM_HASH_SIZE);
   return 0;
   }

/****************************************************************************/
/*                                                                          */
/*  Create PCR_INFO structure using current PCR values                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_GenPCRInfo(uint32_t pcrmap, unsigned char *pcrinfo, uint32_t *len)
   {
   struct pcrinfo
      {
      uint16_t selsize;
      unsigned char select[TPM_PCR_MASK_SIZE];
      unsigned char relhash[TPM_HASH_SIZE];
      unsigned char crthash[TPM_HASH_SIZE];
      } myinfo;
   uint32_t i;
   int j;
   uint32_t work;
   unsigned char *valarray;
   uint32_t numregs;
   uint32_t ret;
   uint32_t valsize;
   SHA_CTX sha;
   
   
   /* check arguments */
   if (pcrinfo == NULL || len == NULL) return ERR_NULL_ARG;
   /* build pcr selection array */
   work = pcrmap;
   memset(myinfo.select,0,TPM_PCR_MASK_SIZE);
   for (i = 0; i < TPM_PCR_MASK_SIZE; ++i)
      {
      myinfo.select[i] = work & 0x000000FF;
      work = work >> 8;
      }
   /* calculate number of PCR registers requested */
   numregs = 0;
   work = pcrmap;
   for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i)
      {
      if (work & 1) ++numregs;
      work = work >> 1;
      }
   if (numregs == 0)
      {
      *len = 0;
      return 0;
      }
   /* create the array of PCR values */
   valarray = (unsigned char *)malloc(TPM_HASH_SIZE * numregs);
   /* read the PCR values into the value array */
   work = pcrmap;
   j = 0;
   for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i, work = work >> 1)
      {
      if ((work & 1) == 0) continue;
      ret = TPM_PcrRead(i,&(valarray[(j*TPM_HASH_SIZE)]));
      if (ret) return ret;
      ++j;
      }
   myinfo.selsize = ntohs(TPM_PCR_MASK_SIZE);
   valsize = ntohl(numregs * TPM_HASH_SIZE);
   /* calculate composite hash */
   SHA1_Init(&sha);
   SHA1_Update(&sha,&myinfo.selsize,TPM_U16_SIZE);
   SHA1_Update(&sha,&myinfo.select,TPM_PCR_MASK_SIZE);
   SHA1_Update(&sha,&valsize,TPM_U32_SIZE);
   for (i = 0;i < numregs;++i)
      {
      SHA1_Update(&sha,&(valarray[(i*TPM_HASH_SIZE)]),TPM_HASH_SIZE);
      }
   SHA1_Final(myinfo.relhash,&sha);
   memcpy(myinfo.crthash,myinfo.relhash,TPM_HASH_SIZE);
   memcpy(pcrinfo,&myinfo,sizeof (struct pcrinfo));
   *len = sizeof (struct pcrinfo);
   return 0;
   }


/****************************************************************************/
/*                                                                          */
/* Reset the indicated PCRs                                                 */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* pcrmap : The selection of PCRs to reset as 32 bit bitmap                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_PCRReset(TPM_PCR_SELECTION * selection)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_PCR_Reset);
	STACK_TPM_BUFFER(tpmdata)
	struct tpm_buffer *serPCRMap = TSS_AllocTPMBuffer(TPM_U16_SIZE + selection->sizeOfSelect + 10);
	uint32_t serPCRMapSize;

	if (NULL == serPCRMap) {
		return ERR_MEM_ERR;
	}

	ret = TPM_WritePCRSelection(serPCRMap, selection);
	if ((ret & ERR_MASK) != 0) {
		TSS_FreeTPMBuffer(serPCRMap);
		return ret;
	}
	serPCRMapSize = ret;

	ret = TSS_buildbuff("00 c1 T l %",&tpmdata,
                                     ordinal_no,
                                       serPCRMapSize, serPCRMap->buffer);

	TSS_FreeTPMBuffer(serPCRMap);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = TPM_Transmit(&tpmdata,"PCR Reset");

	return ret;
}

