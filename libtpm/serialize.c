/********************************************************************************/
/*										*/
/*			     	TPM Serializing Routines 			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: serialize.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpm_structures.h"
#include "tpmkeys.h"
#include "tpmfunc.h"

#include "newserialize.h"

uint32_t TPM_WritePCRComposite(struct tpm_buffer *buffer, TPM_PCR_COMPOSITE * comp)
{
	uint32_t ret;
	if (0 == comp->select.sizeOfSelect) {
		comp->select.sizeOfSelect = sizeof(comp->select.pcrSelect);
		memset(comp->select.pcrSelect,
		       0x0, 
		       comp->select.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_PCR_COMPOSITE, buffer,
	                      PARAMS_TPM_PCR_COMPOSITE_W(comp));

	return ret;
}

uint32_t TPM_ReadPCRComposite(const struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_COMPOSITE *tpc)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_PCR_COMPOSITE, buffer, offset,
	                      PARAMS_TPM_PCR_COMPOSITE_R(tpc));
	return ret;
}

uint32_t TPM_ReadPCRInfoLong(struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_INFO_LONG *info)
{
	return TSS_parsebuff(FORMAT_TPM_PCR_INFO_LONG, buffer, offset,
	                       PARAMS_TPM_PCR_INFO_LONG_R(info));
}

uint32_t TPM_WritePCRInfoLong(struct tpm_buffer *buffer, TPM_PCR_INFO_LONG * info)
{
	uint32_t ret;
	if (0 == info->creationPCRSelection.sizeOfSelect) {
		info->creationPCRSelection.sizeOfSelect = sizeof(info->creationPCRSelection.pcrSelect);
		memset(info->creationPCRSelection.pcrSelect,
		       0x0, 
		       info->creationPCRSelection.sizeOfSelect);
	}
	if (0 == info->releasePCRSelection.sizeOfSelect) {
		info->releasePCRSelection.sizeOfSelect = sizeof(info->releasePCRSelection.pcrSelect);
		memset(info->releasePCRSelection.pcrSelect,
		       0x0, 
		       info->releasePCRSelection.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_PCR_INFO_LONG, buffer,
	                      PARAMS_TPM_PCR_INFO_LONG_W(info));
	return ret;
}

uint32_t TPM_WritePCRInfoShort(struct tpm_buffer *buffer, TPM_PCR_INFO_SHORT *info)
{
	uint32_t ret;
	if (0 == info->pcrSelection.sizeOfSelect) {
		info->pcrSelection.sizeOfSelect = sizeof(info->pcrSelection.pcrSelect);
		memset(info->pcrSelection.pcrSelect,
		       0x0, 
		       info->pcrSelection.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_PCR_INFO_SHORT, buffer, 
	                    PARAMS_TPM_PCR_INFO_SHORT_W(info));

	return ret;
}

uint32_t TPM_ReadPCRInfoShort(const struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_INFO_SHORT *info)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_PCR_INFO_SHORT, buffer, offset,
	                      PARAMS_TPM_PCR_INFO_SHORT_R(info));
	return ret;	
}


uint32_t TPM_WritePCRInfo(struct tpm_buffer *buffer, TPM_PCR_INFO * info)
{
	uint32_t ret;
	if (0 == info->pcrSelection.sizeOfSelect) {
		info->pcrSelection.sizeOfSelect = sizeof(info->pcrSelection.pcrSelect);
		memset(info->pcrSelection.pcrSelect,
		       0x0, 
		       info->pcrSelection.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_PCR_INFO, buffer,
	                      PARAMS_TPM_PCR_INFO_W(info));
	return ret;
}

uint32_t TPM_ReadPCRInfo(struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_INFO *info)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_PCR_INFO, buffer, offset,
	                      PARAMS_TPM_PCR_INFO_R(info));
	return ret;
}

uint32_t TPM_WriteStoreAsymkey(struct tpm_buffer *buffer, TPM_STORE_ASYMKEY * sak)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_STORE_ASYMKEY, buffer,
	                      PARAMS_TPM_STORE_ASYMKEY_W(sak));
	return ret;
}

uint32_t TPM_ReadStoredData(struct tpm_buffer *buffer, uint32_t offset, TPM_STORED_DATA *sd)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_STORED_DATA, buffer, offset,
	                      PARAMS_TPM_STORED_DATA_R(sd));
	return ret;
}

uint32_t TPM_WriteStoredData(struct tpm_buffer *buffer, TPM_STORED_DATA *sd)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_STORED_DATA, buffer,
	                     PARAMS_TPM_STORED_DATA_W(sd));
	return ret;
}


uint32_t TPM_HashPCRComposite(TPM_PCR_COMPOSITE * comp, unsigned char * digest)
{
	int len;
	struct tpm_buffer *buffer = TSS_AllocTPMBuffer(comp->pcrValue.size + sizeof(TPM_PCR_COMPOSITE));
	if (NULL != buffer) {
		len = TPM_WritePCRComposite(buffer, comp);
		TSS_sha1(buffer->buffer, len, digest);
		TSS_FreeTPMBuffer(buffer);
	} else {
		return ERR_MEM_ERR;
	}
	return 0;
}

uint32_t TPM_WritePCRSelection(struct tpm_buffer *buffer, TPM_PCR_SELECTION * sel) 
{
	uint32_t ret;
	if (0 == sel->sizeOfSelect) {
		sel->sizeOfSelect = sizeof(sel->pcrSelect);
		memset(sel->pcrSelect,
		       0x0, 
		       sel->sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_PCR_SELECTION, buffer,
	                    PARAMS_TPM_PCR_SELECTION_W(sel));
	return ret;
}

uint32_t TPM_ReadPCRSelection(struct tpm_buffer *buffer, uint32_t offset,
                              TPM_PCR_SELECTION *sel) 
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_PCR_SELECTION, buffer, offset,
	                    PARAMS_TPM_PCR_SELECTION_R(sel));
	return ret;
}


uint32_t TPM_WriteMSAComposite(struct tpm_buffer *buffer, TPM_MSA_COMPOSITE * comp)
{
	uint32_t ret;
	ret = TSS_buildbuff("L %", buffer,
	                     comp->MSAlist,
	                       comp->MSAlist * TPM_HASH_SIZE, comp->migAuthDigest);
	return ret;
}

uint32_t TPM_HashMSAComposite(TPM_MSA_COMPOSITE * comp, unsigned char * digest)
{
	uint32_t ret = 0;
	struct tpm_buffer *buffer = TSS_AllocTPMBuffer(comp->MSAlist * TPM_HASH_SIZE + TPM_U32_SIZE);
	if (NULL != buffer) {
		uint32_t len = TPM_WriteMSAComposite(buffer, comp);
		TSS_sha1(buffer->buffer, len, digest);
		TSS_FreeTPMBuffer(buffer);
		
	} else {
		ret = ERR_MEM_ERR;
	}
	return ret;
}

uint32_t TPM_ReadMSAFile(const char * filename, TPM_MSA_COMPOSITE * msaList)
{
	uint32_t ret;
	unsigned char * buffer = NULL;
	uint32_t buffersize = 0;
	ret = TPM_ReadFile(filename, &buffer, &buffersize);
	if ( (ret & ERR_MASK) != 0 ) {
		return ret;
	}
	msaList->MSAlist = LOAD32(buffer, 0);
	if (msaList->MSAlist * TPM_HASH_SIZE + 4 == buffersize) {
		msaList->migAuthDigest = malloc( msaList->MSAlist * TPM_HASH_SIZE );
		if (NULL == msaList->migAuthDigest) {
			return ERR_MEM_ERR;
		}
		memcpy(msaList->migAuthDigest,
		       buffer+sizeof(uint32_t),
		       msaList->MSAlist * TPM_HASH_SIZE);
	} else {
		return ERR_BAD_FILE;
	}
	return 0;
}

uint32_t TPM_WriteCMKAuth(struct tpm_buffer *buffer, TPM_CMK_AUTH * auth) 
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_CMK_AUTH, buffer,
	                      PARAMS_TPM_CMK_AUTH_W(auth));
	return ret;
}

uint32_t TPM_HashCMKAuth(TPM_CMK_AUTH * auth, unsigned char * hash)
{
	STACK_TPM_BUFFER(buffer)
	uint32_t len;
	uint32_t ret = TPM_WriteCMKAuth(&buffer, auth);
	if ( (ret & ERR_MASK) != 0) {
		return ret;
	}
	len = ret;

	TSS_sha1(buffer.buffer, len, hash);
	return 0;
}


uint32_t TPM_WriteMigrationKeyAuth(struct tpm_buffer *buffer, TPM_MIGRATIONKEYAUTH * mka) 
{
	uint32_t ret;
//	#warning Function not completely implemented!
	ret = TSS_buildbuff("     s %", buffer,
	                     
	                          mka->migrationScheme,
	                            TPM_DIGEST_SIZE, mka->digest);
	return ret;
}

uint32_t TPM_WriteEkBlobActivate(struct tpm_buffer *buffer, TPM_EK_BLOB_ACTIVATE * blob) {
	uint32_t ret = 0;
	
	if (0 == blob->pcrInfo.pcrSelection.sizeOfSelect) {
		blob->pcrInfo.pcrSelection.sizeOfSelect = sizeof(blob->pcrInfo.pcrSelection.pcrSelect);
		memset(blob->pcrInfo.pcrSelection.pcrSelect,
		       0x0, 
		       blob->pcrInfo.pcrSelection.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_EK_BLOB_ACTIVATE, buffer,
	                      PARAMS_TPM_EK_BLOB_ACTIVATE_W(blob));
	return ret;
}


uint32_t TPM_WriteEkBlob(struct tpm_buffer *buffer, TPM_EK_BLOB * blob) {
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_EK_BLOB, buffer,
	                      PARAMS_TPM_EK_BLOB_W(blob));
	return ret;
}

uint32_t TPM_WriteCAContents(struct tpm_buffer *buffer, TPM_ASYM_CA_CONTENTS * data) {
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_ASYM_CA_CONTENTS, buffer,
	                     PARAMS_TPM_ASYM_CA_CONTENTS_W(data));
	return ret;
}

uint32_t TPM_WriteDelegatePublic(struct tpm_buffer *buffer, TPM_DELEGATE_PUBLIC * pub)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_DELEGATE_PUBLIC,buffer,
	                      PARAMS_TPM_DELEGATE_PUBLIC_W(pub));
	return ret;
}

uint32_t TPM_WriteDelegateOwnerBlob(struct tpm_buffer *buffer, TPM_DELEGATE_OWNER_BLOB * blob)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_DELEGATE_OWNER_BLOB, buffer,
	                    PARAMS_TPM_DELEGATE_OWNER_BLOB_W(blob));
	return ret;
}


uint32_t TPM_HashPubKey(keydata * pubkey, unsigned char * digest) 
{
	STACK_TPM_BUFFER(buffer)
	uint32_t len = TPM_WriteKeyPub(&buffer, pubkey);
	if ((len & ERR_MASK) == 0) {
		TSS_sha1(buffer.buffer, len, digest);
	}
	return len;
}



uint32_t TPM_ReadFile(const char * filename, unsigned char ** buffer, uint32_t * buffersize)
{
	uint32_t ret = 0;
	struct stat _stat;
	if (0 == stat(filename, &_stat)) {
		*buffer = (unsigned char *)malloc(_stat.st_size);
		*buffersize = (uint32_t)_stat.st_size;
		if (NULL != *buffer) {
			FILE * f = fopen(filename, "r");
			if (NULL != f) {
				if ((size_t)_stat.st_size != fread(*buffer, 1, _stat.st_size, f)) {
					free(*buffer);
					*buffer = NULL;
					*buffersize = 0;
					ret = ERR_BAD_FILE;
				}
				if (fclose(f) != 0)
					ret = ERR_BAD_FILE_CLOSE;
			} else {
				free(*buffer);
				*buffersize = 0;
				ret = ERR_BAD_FILE;
			}
		} else {
			ret = ERR_MEM_ERR;
		}
	} else {
		ret = ERR_BAD_FILE;
	}
	
	return ret;
}

uint32_t TPM_WriteFile(const char * filename, unsigned char * buffer, uint32_t buffersize)
{
	uint32_t ret = 0;
	if (buffer == NULL) {
		return ERR_BUFFER;
	}
	FILE * f = fopen(filename, "w");
	if (NULL != f) {
		if (buffersize != fwrite(buffer, 1, buffersize,f)) {
			ret = ERR_BAD_FILE;
		}
		if (fclose(f) != 0)
			ret = ERR_BAD_FILE_CLOSE;
	} else {
		ret = ERR_BAD_FILE;
	}
	
	return ret;
}

uint32_t TPM_ReadKeyfile(const char * filename, keydata * k)
{
	unsigned char * buffer = NULL;
	uint32_t buffersize = 0;
	uint32_t ret = TPM_ReadFile(filename, &buffer, &buffersize);

	if ( (ret & ERR_MASK) == 0 ) {
	        STACK_TPM_BUFFER( buf);
	        SET_TPM_BUFFER(&buf, buffer, buffersize);
		memset(k,0x0,sizeof(keydata));
		if (buffersize != TSS_KeyExtract(&buf, 0, k)) {
			ret = ERR_BAD_FILE;
		}
		free(buffer);
	}
	return ret;
}

uint32_t TPM_ReadPubKeyfile(const char * filename, pubkeydata *pubk)
{
	unsigned char * buffer = NULL;
	uint32_t buffersize = 0;
	uint32_t ret = TPM_ReadFile(filename, &buffer, &buffersize);

	if ( (ret & ERR_MASK) == 0 ) {
	        STACK_TPM_BUFFER( buf);
	        SET_TPM_BUFFER(&buf, buffer, buffersize);
		memset(pubk,0x0,sizeof(*pubk));
		if (buffersize != TSS_PubKeyExtract(&buf, 0, pubk)) {
			ret = ERR_BAD_FILE;
		}
		free(buffer);
	}
	return ret;
}


//!!! Change this
uint32_t TPM_GetCertifyInfoSize(const unsigned char * blob)
{
	uint16_t tag = LOAD16(blob, 0);
	uint32_t offset = sizeof(TPM_STRUCTURE_TAG) +
			  sizeof(BYTE) +
			  sizeof(TPM_PAYLOAD_TYPE) +
	                  sizeof(TPM_KEY_USAGE) +
	                  sizeof(TPM_KEY_FLAGS) +
	                  sizeof(TPM_AUTH_DATA_USAGE) +
	                  sizeof(TPM_ALGORITHM_ID) +
	                  sizeof(TPM_ENC_SCHEME) +
	                  sizeof(TPM_SIG_SCHEME);
	uint32_t parmSize;
	uint32_t size;	
	parmSize = LOAD32(blob,offset);
	offset += sizeof(uint32_t) +
	          parmSize +
	          sizeof(TPM_DIGEST) +
	          sizeof(TPM_NONCE) +
	          sizeof(TPM_BOOL);
	size = LOAD32(blob,offset);
	offset += sizeof(uint32_t) +
	          size;
	if (TPM_TAG_CERTIFY_INFO2 == tag) {
		size = LOAD32(blob,offset);
		offset += sizeof(uint32_t) +
		          size;
	}
	return offset;
}

uint32_t TPM_ReadKeyParms(const struct tpm_buffer *tb, uint32_t offset , TPM_KEY_PARMS * keyparms)
{
	return TSS_parsebuff(FORMAT_TPM_KEY_PARMS, tb, offset,
	                     PARAMS_TPM_KEY_PARMS_R(keyparms));
}


uint32_t TPM_ReadCertifyInfo(const struct tpm_buffer *tb, uint32_t offset, TPM_CERTIFY_INFO * cinfo)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_CERTIFY_INFO, tb, offset, 
	                     PARAMS_TPM_CERTIFY_INFO_R(cinfo));


	return ret;
}

uint32_t TPM_ReadCertifyInfo2(const struct tpm_buffer *tb, uint32_t offset, TPM_CERTIFY_INFO2 * cinfo)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_CERTIFY_INFO2, tb, offset, 
	                     PARAMS_TPM_CERTIFY_INFO2_R(cinfo));
	if ((ret & ERR_MASK))
		return ret;
	if (cinfo->tag != TPM_TAG_CERTIFY_INFO2)
		return ERR_STRUCTURE;
	return ret;
}


uint32_t TPM_WriteQuoteInfo2(struct tpm_buffer *buffer, TPM_QUOTE_INFO2 * info2)
{
	uint32_t ret = 0;

	if (0 == info2->infoShort.pcrSelection.sizeOfSelect) {
		info2->infoShort.pcrSelection.sizeOfSelect = sizeof(info2->infoShort.pcrSelection.pcrSelect);
		memset(info2->infoShort.pcrSelection.pcrSelect,
		       0x0, 
		       info2->infoShort.pcrSelection.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_QUOTE_INFO2, buffer,
	                    PARAMS_TPM_QUOTE_INFO2_W(info2));
	return ret;
}

uint32_t TPM_WriteQuoteInfo(struct tpm_buffer *buffer, TPM_QUOTE_INFO * info)
{
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_QUOTE_INFO, buffer,
	                    PARAMS_TPM_QUOTE_INFO_W(info));
	return ret;
}

uint32_t TPM_WriteContextBlob(struct tpm_buffer *buffer, TPM_CONTEXT_BLOB * context)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_CONTEXT_BLOB, buffer,
	                      PARAMS_TPM_CONTEXT_BLOB_W(context));
	return ret;
}

uint32_t TPM_ReadContextBlob(const struct tpm_buffer *buffer,
                             uint32_t offset,
                             TPM_CONTEXT_BLOB *context)
{
	uint32_t ret;

	ret = TSS_parsebuff(FORMAT_TPM_CONTEXT_BLOB, buffer, offset,
	                      PARAMS_TPM_CONTEXT_BLOB_R(context));
	if ((ret & ERR_MASK))
		return ret;
	if (context->tag != TPM_TAG_CONTEXTBLOB)
		return ERR_STRUCTURE; 
	return ret;
}


uint32_t TPM_WritePubInfo(TPM_NV_DATA_PUBLIC * pub,
                           struct tpm_buffer *buffer) {
	uint32_t ret;

	if (0 == pub->pcrInfoWrite.pcrSelection.sizeOfSelect) {
		pub->pcrInfoWrite.pcrSelection.sizeOfSelect = sizeof(pub->pcrInfoWrite.pcrSelection.pcrSelect);
		memset(pub->pcrInfoWrite.pcrSelection.pcrSelect,
		       0x0, 
		       pub->pcrInfoWrite.pcrSelection.sizeOfSelect);
	}
	if (0 == pub->pcrInfoRead.pcrSelection.sizeOfSelect) {
		pub->pcrInfoRead.pcrSelection.sizeOfSelect = sizeof(pub->pcrInfoRead.pcrSelection.pcrSelect);
		memset(pub->pcrInfoRead.pcrSelection.pcrSelect,
		       0x0, 
		       pub->pcrInfoRead.pcrSelection.sizeOfSelect);
	}
	ret = TSS_buildbuff(FORMAT_TPM_NV_DATA_PUBLIC, buffer,
	                    PARAMS_TPM_NV_DATA_PUBLIC_W(pub));
	return ret;
}


/* the most recent permanent flags */
uint32_t TPM_ReadPermanentFlags(const struct tpm_buffer * tb,
                                uint32_t offset, 
                                TPM_PERMANENT_FLAGS * pf,
				uint32_t used)
{
	uint32_t ret;
	/* rev 62 */
	if (used == 17) {
	    ret = TSS_parsebuff(FORMAT_TPM_PERMANENT_FLAGS17, tb, offset,
				PARAMS_TPM_PERMANENT_FLAGS17_R(pf));
	}
	/* rev 85 Atmel */
	else if (used == 20) {
		ret = TSS_parsebuff(FORMAT_TPM_PERMANENT_FLAGS20, tb, offset,
				    PARAMS_TPM_PERMANENT_FLAGS20_R(pf));
	}
	/* rev 85, 94 */
	else if (used == 21) {
	    ret = TSS_parsebuff(FORMAT_TPM_PERMANENT_FLAGS21, tb, offset,
				PARAMS_TPM_PERMANENT_FLAGS21_R(pf));
	}
	/* rev 103 */
	else if (used == 22) {
	    ret = TSS_parsebuff(FORMAT_TPM_PERMANENT_FLAGS22, tb, offset,
				PARAMS_TPM_PERMANENT_FLAGS22_R(pf));
	}
	else {
	    ret = ERR_STRUCTURE;
	}
	if ((ret & ERR_MASK))
	    return ret;
	/* compliant TPM */
	if (used != 20) {
	    if (pf->tag != TPM_TAG_PERMANENT_FLAGS) {
		return ERR_STRUCTURE;
	    }
	}
	/* Atmel rev 85 TPM */
	if (used == 20) {
	    if (pf->tag != TPM_TAG_PERSISTENT_FLAGS) {
		return ERR_STRUCTURE;
	    }
	}
	return ret;
}

uint32_t TPM_ReadSTClearFlags(const struct tpm_buffer *tb,
                              uint32_t offset, 
                              TPM_STCLEAR_FLAGS * sf) 
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_STCLEAR_FLAGS, tb, offset,
	                      PARAMS_TPM_STCLEAR_FLAGS_R(sf));

	if ((ret & ERR_MASK))
		return ret;
	if (sf->tag != TPM_TAG_STCLEAR_FLAGS)
		return ERR_STRUCTURE;
	return ret;
}

uint32_t TPM_ReadNVDataPublic(const struct tpm_buffer *tb, 
                              uint32_t offset, 
                              TPM_NV_DATA_PUBLIC * ndp)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_NV_DATA_PUBLIC, tb, offset,
	                      PARAMS_TPM_NV_DATA_PUBLIC_R(ndp));
	return ret;
}

uint32_t TPM_ReadCapVersionInfo(const struct tpm_buffer *tb, uint32_t offset, TPM_CAP_VERSION_INFO * cvi)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_CAP_VERSION_INFO, tb, offset,
	                    PARAMS_TPM_CAP_VERSION_INFO_R(cvi));
	return ret;
}

uint32_t TPM_ReadStartupEffects(const unsigned char * buffer, TPM_STARTUP_EFFECTS * se)
{
	uint32_t offset = 0;
	*se = LOAD32(buffer, offset);   offset += 4;
	return offset;
}

/****************************************************************************/
/*                                                                          */
/* Create a buffer from a keydata structure                                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_WriteKey(struct tpm_buffer *buffer, keydata *k)
{
   uint32_t ret;
   
   if (k->v.tag == TPM_TAG_KEY12) {
      uint16_t filler = 0;
      ret = TSS_buildbuff(FORMAT_TPM_KEY12_EMB_RSA, buffer,
                          PARAMS_TPM_KEY12_EMB_RSA_W(k));
   } else {
      ret = TSS_buildbuff(FORMAT_TPM_KEY_EMB_RSA, buffer,
                          PARAMS_TPM_KEY_EMB_RSA_W(k));
   }
   return ret;
}

uint32_t TPM_ReadKey(const struct tpm_buffer *tb, uint32_t offset, keydata *k)
{
	uint32_t ret;
	uint16_t filler = 0;
	/* 
	 * must first try to parse as a 1.2 key, then later as an 
	 * old-style key.
	 */
	ret = TSS_parsebuff(FORMAT_TPM_KEY12_EMB_RSA, tb, offset,
	                     PARAMS_TPM_KEY12_EMB_RSA_R(k));
	if (ret > 0) {
		if (k->v.tag != TPM_TAG_KEY12) {
			ret = TSS_parsebuff(FORMAT_TPM_KEY_EMB_RSA, tb, offset,
			                     PARAMS_TPM_KEY_EMB_RSA_R(k));
		}
	}
	return ret;
}

uint32_t TPM_WriteKeyInfo(struct tpm_buffer *buffer, keydata *k)
{
	uint32_t ret;

	ret = TSS_buildbuff(FORMAT_TPM_KEY_PARMS_EMB_RSA, buffer,
	                    PARAMS_TPM_KEY_PARMS_EMB_RSA_W(&k->pub.algorithmParms));
	return ret;
}


uint32_t TPM_WriteKeyPub(struct tpm_buffer *buffer, keydata * k)
{
	uint32_t ret = -1;
	switch (k->pub.algorithmParms.algorithmID) {
		case TPM_ALG_RSA:
			ret = TSS_buildbuff(FORMAT_TPM_PUBKEY_EMB_RSA, buffer,
			                    PARAMS_TPM_PUBKEY_EMB_RSA_W(&k->pub));
		break;
		
		case TPM_ALG_AES128:
		case TPM_ALG_AES192:
		case TPM_ALG_AES256:
			ret = TSS_buildbuff(FORMAT_TPM_PUBKEY_EMB_SYM, buffer,
			                    PARAMS_TPM_PUBKEY_EMB_SYM_W(&k->pub));
		break;
		
		default:
			ret = ERR_BAD_ARG;
		break;
	}
	return ret;
}



uint32_t TPM_WriteSymmetricKey(struct tpm_buffer *buffer, TPM_SYMMETRIC_KEY * key)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_SYMMETRIC_KEY, buffer, 
	                    PARAMS_TPM_SYMMETRIC_KEY_W(key));
	return ret;
}


uint32_t TPM_ReadSymmetricKey(struct tpm_buffer *tb, uint32_t offset, TPM_SYMMETRIC_KEY * key) {
	return TSS_parsebuff(FORMAT_TPM_SYMMETRIC_KEY, tb, offset,
	                     PARAMS_TPM_SYMMETRIC_KEY_R(key));
}

uint32_t TPM_WriteTPMFamilyLabel(struct tpm_buffer *buffer, TPM_FAMILY_LABEL l)
{
	uint32_t ret;
	ret = TSS_buildbuff("o", buffer,
	                     l);
	return ret;
}

uint32_t TPM_ReadTPMFamilyLabel(const unsigned char *buffer, TPM_FAMILY_LABEL *l)
{
	uint32_t offset = 0;
	*l = buffer[0];   offset += 1;
	return offset;
}

uint32_t TPM_WriteTPMDelegations(struct tpm_buffer *buffer,
                                 TPM_DELEGATIONS *td)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_DELEGATIONS, buffer,
	                    PARAMS_TPM_DELEGATIONS_W(td));
	return ret;
}

uint32_t TPM_ReadTPMDelegations(const struct tpm_buffer *buffer, uint32_t offset,
                                TPM_DELEGATIONS *td)
{
	return TSS_parsebuff(FORMAT_TPM_DELEGATIONS, buffer, offset,
	                     PARAMS_TPM_DELEGATIONS_R(td));
}
uint32_t TPM_WriteTPMDelegatePublic(struct tpm_buffer *buffer,
                                    TPM_DELEGATE_PUBLIC * tdp)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_DELEGATE_PUBLIC, buffer,
	                    PARAMS_TPM_DELEGATE_PUBLIC_W(tdp));
	return ret;
}

uint32_t TPM_WriteTPMDelegateOwnerBlob(struct tpm_buffer *buffer,
                                       TPM_DELEGATE_OWNER_BLOB *tdob)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_DELEGATE_OWNER_BLOB, buffer,
	                    PARAMS_TPM_DELEGATE_OWNER_BLOB_W(tdob));
	return ret;
}

uint32_t TPM_WriteTPMDelegateKeyBlob(struct tpm_buffer *buffer,
                                     TPM_DELEGATE_KEY_BLOB *tdob)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_DELEGATE_KEY_BLOB, buffer,
	                    PARAMS_TPM_DELEGATE_KEY_BLOB_W(tdob));
	return ret;
}



uint32_t TPM_ReadFamilyTableEntry(struct tpm_buffer *buffer,
                                  uint32_t offset,
                                  TPM_FAMILY_TABLE_ENTRY *fte)
{
	return TSS_parsebuff(FORMAT_TPM_FAMILY_TABLE_ENTRY, buffer, offset,
	                     PARAMS_TPM_FAMILY_TABLE_ENTRY_R(fte));
} 

uint32_t TPM_ReadDelegatePublic(struct tpm_buffer *buffer,
                                uint32_t offset,
                                TPM_DELEGATE_PUBLIC *dp)
{
	return TSS_parsebuff(FORMAT_TPM_DELEGATE_PUBLIC, buffer, offset,
	                     PARAMS_TPM_DELEGATE_PUBLIC_R(dp));
}

uint32_t TPM_GetCurrentTicks(const struct tpm_buffer *tb,
                             uint32_t offset, 
                             TPM_CURRENT_TICKS * ticks) 
{
	return TSS_parsebuff(FORMAT_TPM_CURRENT_TICKS, tb, offset,
	                     PARAMS_TPM_CURRENT_TICKS_R(ticks));
}


uint32_t TPM_ReadCounterValue(const unsigned char * buffer, 
                              TPM_COUNTER_VALUE * counter)
{
	uint32_t offset = 0;
	counter->tag = LOAD16(buffer, offset);               offset += TPM_U16_SIZE;
	if (counter->tag != TPM_TAG_COUNTER_VALUE)
		return ERR_STRUCTURE;
	memcpy(&counter->label[0], 
	       &buffer[offset], 
	       sizeof(counter->label)); offset += sizeof(counter->label);

	
	counter->counter = LOAD32(buffer, offset);
	return 0;
}

uint32_t TPM_WriteCounterValue(struct tpm_buffer *tb, 
                               TPM_COUNTER_VALUE * ctr)
{
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_COUNTER_VALUE, tb,
	                    PARAMS_TPM_COUNTER_VALUE_W(ctr));
	return ret;
}


uint32_t TPM_WriteSignInfo(struct tpm_buffer *tb,
                           TPM_SIGN_INFO *tsi)
{
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_SIGN_INFO, tb,
	                    PARAMS_TPM_SIGN_INFO_W(tsi));
	return ret;
}

uint32_t TPM_WriteTransportPublic(struct tpm_buffer *tb,
                                  TPM_TRANSPORT_PUBLIC *ttp)
{
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_TRANSPORT_PUBLIC, tb,
	                    PARAMS_TPM_TRANSPORT_PUBLIC_W(ttp));
	return ret;
}

uint32_t TPM_WriteTransportAuth(struct tpm_buffer *tb,
                                TPM_TRANSPORT_AUTH *tta)
{
	uint32_t ret = 0;
	ret = TSS_buildbuff(FORMAT_TPM_TRANSPORT_AUTH, tb,
	                    PARAMS_TPM_TRANSPORT_AUTH_W(tta));
	return ret;
}

uint32_t TPM_WriteAuditEventIn(struct tpm_buffer *buffer, TPM_AUDIT_EVENT_IN * aei)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_AUDIT_EVENT_IN, buffer,
	                      PARAMS_TPM_AUDIT_EVENT_IN_W(aei));
	return ret;
}

uint32_t TPM_WriteAuditEventOut(struct tpm_buffer *buffer, TPM_AUDIT_EVENT_OUT * aeo)
{
	uint32_t ret;
	ret = TSS_buildbuff(FORMAT_TPM_AUDIT_EVENT_OUT, buffer,
	                      PARAMS_TPM_AUDIT_EVENT_OUT_W(aeo));
	return ret;
}

uint32_t TPM_ReadDAInfo(struct tpm_buffer *buffer,
                        uint32_t offset,
                        TPM_DA_INFO *tdi)
{
	return TSS_parsebuff(FORMAT_TPM_DA_INFO, buffer, offset,
	                     PARAMS_TPM_DA_INFO_R(tdi));
} 

uint32_t TPM_ReadDAInfoLimited(struct tpm_buffer *buffer,
                               uint32_t offset,
                               TPM_DA_INFO_LIMITED *tdil)
{
	return TSS_parsebuff(FORMAT_TPM_DA_INFO_LIMITED, buffer, offset,
	                     PARAMS_TPM_DA_INFO_LIMITED_R(tdil));
} 

uint32_t TPM_WriteTransportLogIn(struct tpm_buffer *buffer,
                                 TPM_TRANSPORT_LOG_IN *ttli)
{
	return TSS_buildbuff(FORMAT_TPM_TRANSPORT_LOG_IN, buffer,
	                     PARAMS_TPM_TRANSPORT_LOG_IN_W(ttli));
}

uint32_t TPM_WriteTransportLogOut(struct tpm_buffer *buffer,
                                  TPM_TRANSPORT_LOG_OUT *ttlo)
{
	return TSS_buildbuff(FORMAT_TPM_TRANSPORT_LOG_OUT, buffer,
	                     PARAMS_TPM_TRANSPORT_LOG_OUT_W(ttlo));
}

uint32_t TPM_WriteCurrentTicks(struct tpm_buffer *buffer,
			       TPM_CURRENT_TICKS *tct)
{
	return TSS_buildbuff(FORMAT_TPM_CURRENT_TICKS, buffer,
	                     PARAMS_TPM_CURRENT_TICKS_W(tct));
}

uint32_t TPM_ReadCurrentTicks(struct tpm_buffer *buffer,
                              uint32_t offset,
			      TPM_CURRENT_TICKS *tct)
{
	return TSS_parsebuff(FORMAT_TPM_CURRENT_TICKS, buffer, offset,
	                     PARAMS_TPM_CURRENT_TICKS_R(tct));
}

/****************************************************************************/
/*                                                                          */
/* Walk down a Key blob extracting information                              */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_KeyExtract(const struct tpm_buffer *tb, uint32_t offset, 
                        keydata *k)
{
	return TPM_ReadKey(tb, offset, k);
}

/****************************************************************************/
/*                                                                          */
/* Walk down a Public Key blob extracting information                       */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_PubKeyExtract(const struct tpm_buffer *tb, uint32_t offset,
                           pubkeydata *k)
{
	uint32_t ret;
	ret = TSS_parsebuff(FORMAT_TPM_PUBKEY_EMB_RSA, tb, offset,
	                    PARAMS_TPM_PUBKEY_EMB_RSA_R(k));
	return ret;
}
