/********************************************************************************/
/*										*/
/*			     	TPM Transport Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: transport.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <openssl/aes.h>
#include <tpm.h>
#include <tpmfunc.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tpm_types.h>
#include <tpm_constants.h>
#include "tpmutil.h"

uint32_t g_num_transports;
uint32_t (*g_transportFunction[TPM_MAX_TRANSPORTS])(struct tpm_buffer *tb, const char *msg);

static session *g_transSession[TPM_MAX_TRANSPORTS];

/****************************************************************************/
/*                                                                          */
/* Functions for handling the trans digest                                  */
/*                                                                          */
/****************************************************************************/

/**
 * Calculate the transdigest for the EstablishTransport function.
 * Perform calculations on TPM_TRANSPORT_LOG_IN structure and
 * return the transdigest as calculated in step 8) a) iii) (rev. 100)
 * 
 */
static
uint32_t _calc_transdigest(TPM_COMMAND_CODE ordinal,
                           TPM_TRANSPORT_PUBLIC *ttp,
                           struct tpm_buffer *secret,
                           TPM_DIGEST *transdigest) {
        TPM_TRANSPORT_LOG_IN ttli;
        uint32_t ret = 0;
        STACK_TPM_BUFFER(buffer);
        STACK_TPM_BUFFER(transPub);
        STACK_TPM_BUFFER(ser_ttli);
        TPM_DIGEST empty;
        
        ret = TPM_WriteTransportPublic(&transPub, ttp);
        if ((ret & ERR_MASK)) {
                return ret;
        }

        /* ordinal || transPublic || SecretSize || secret */
        ret = TSS_buildbuff("L % @", &buffer,
                             ordinal,
                               transPub.used, transPub.buffer,
                                 secret->used, secret->buffer);

        if ((ret & ERR_MASK)) {
                return ret;
        }
        /* L1 -> parameters is SHA1( ... ) */
        TSS_sha1(buffer.buffer, buffer.used, ttli.parameters);
        /* pubkey hash to NULL */
        memset(ttli.pubKeyHash, 0x0, sizeof(ttli.pubKeyHash));
        /* fill other L1 parameters as defined */
        ttli.tag = TPM_TAG_TRANSPORT_LOG_IN;

        ret = TPM_WriteTransportLogIn(&ser_ttli, &ttli);
        if ((ret & ERR_MASK)) {
                return ret;
        }

        memset(empty, 0x0, sizeof(empty));
        
        RESET_TPM_BUFFER(&buffer);
        /* transdigest is 000000... */
        SET_TPM_BUFFER(&buffer, empty, sizeof(empty));
        /* L1 */
        tpm_buffer_store(&buffer, &ser_ttli, 0x0, ser_ttli.used);

        /* calculate T1->transDigest as SHA1(T1->transDigest || L1) */
        TSS_sha1(buffer.buffer, buffer.used, (unsigned char *)transdigest);

#if 0
	print_array("_calc_transdigest: transdigest: ",
		    (unsigned char *)transdigest, TPM_DIGEST_SIZE);
#endif

	ret = 0;
                
        return ret;
}

/**
 *  Get the appropriate filename for the transDigest to write out to
 *  for the TPM_INSTANCE that the library is currently using.
 **/
static
char *_get_transdigest_file(uint32_t handle) {
        char *filename = malloc(50);
	char *instance = getenv("TPM_INSTANCE");
	int inst;
	if (instance == NULL) {
		instance = "0";
	}
	inst = atoi(instance);

	sprintf(filename,"/tmp/.transdigest-%08x-%d", handle, inst);
        return filename;
}


/*
 * Read the value of the transdigest for the TPM_INSTANCE that the
 * library is currently using.
 */
static
uint32_t _read_transdigest(uint32_t handle, unsigned char *digest) {
	uint32_t ret = 0;
	char *filename = _get_transdigest_file(handle);
	if (filename) {
		FILE *file = fopen(filename, "r");
		if (file != NULL) {
			if (1 != fread(digest, TPM_DIGEST_SIZE, 1, file)) {
				ret = ERR_IO;
			}
			fclose(file);
		} else {
			ret = ERR_BAD_FILE;
		}
		free(filename);
	} else {
		ret = ERR_MEM_ERR;
	}
	return ret;
}


/*
 * Write the transdigest for the TPM_INSTANCE that the library
 * is currently using into a file.
 */
static
uint32_t _store_transdigest(uint32_t handle, unsigned char *digest) {
	uint32_t ret = 0;
	char *filename = _get_transdigest_file(handle);
	if (filename) {
		FILE *file = fopen(filename, "w");
		if (file != NULL) {
			if (1 != fwrite(digest, TPM_DIGEST_SIZE, 1, file)) {
				ret = ERR_IO;
			}
			if (fclose(file) != 0)
				ret = ERR_BAD_FILE_CLOSE;
		} else {
			ret = ERR_BAD_FILE;
		}
		free(filename);
	} else {
		ret = ERR_MEM_ERR;
	}
	return ret;
}


/*
 * Extend the transdigest by reading its current value from the
 * file for the TPM_INSTANCE that the library is currently using
 * and calculate 
 *  transdigest_new = SHA1(transdigest || data)
 * and write the new transdigest back into the file.
 */
static
uint32_t _extend_transdigest(uint32_t handle, struct tpm_buffer *data) {
	uint32_t ret = 0;
	char *filename = _get_transdigest_file(handle);
	if (filename) {
		FILE *file = fopen(filename, "r+");
		STACK_TPM_BUFFER(buffer);
		if (file != NULL) {
			if (1 != fread(buffer.buffer, TPM_DIGEST_SIZE, 1, file)) {
				ret = ERR_IO;
			} else {
				TPM_DIGEST digest;
#if 0
				print_array("_extend_transdigest: transdigest in: ", buffer.buffer, TPM_DIGEST_SIZE);
#endif
				buffer.used = TPM_DIGEST_SIZE;
				tpm_buffer_store(&buffer, data, 0, data->used);
				TSS_sha1(buffer.buffer, buffer.used, digest);
				//printf("20 %d \n",data->used);
#if 0
				print_array("_extend_transdigest: transdigest out: ",digest,20);
#endif
				fseek(file, 0, SEEK_SET);
				if (1 != fwrite(digest, TPM_DIGEST_SIZE, 1, file)) {
					ret = ERR_IO;
				}
			}
			fclose(file);
		} else {
			ret = ERR_BAD_FILE;
		}
		free(filename);
	} else {
		ret = ERR_MEM_ERR;
	}
	return ret;
}


/**
 *  Calculate the transdigest for the EstablishTransport function
 *  when it calculates the TPM_TRANSPORT_LOG_OUT function.
 *  Extend the TPM_INSTANCE's transdigest with the calculated value
 *  and write it back into the TPM_INSTANCE's file.
 */
static
uint32_t _calc_logout_esttrans(uint32_t returncode,
                               uint32_t ordinal,
                               uint32_t locality,
                               TPM_CURRENT_TICKS *currentticks,
                               unsigned char *transNonceEven,
                               uint32_t handle) {
	uint32_t ret = 0;
	TPM_TRANSPORT_LOG_OUT ttlo;
	STACK_TPM_BUFFER(buffer);
	STACK_TPM_BUFFER(ser_ttlo);
	STACK_TPM_BUFFER(currentticks_ser);

	ret = TPM_WriteCurrentTicks(&currentticks_ser, currentticks);
	if ((ret & ERR_MASK)) {
		return ret;
	}

        ret = TSS_buildbuff("L L L % %", &buffer,
                             returncode,
                               ordinal,
                                 locality,
                                   currentticks_ser.used, currentticks_ser.buffer,
                                     TPM_NONCE_SIZE, transNonceEven);

	ttlo.tag = TPM_TAG_TRANSPORT_LOG_OUT;
	TSS_sha1(buffer.buffer, buffer.used, ttlo.parameters);
	ttlo.locality = locality;
	memcpy(&ttlo.currentTicks, currentticks, sizeof(ttlo.currentTicks));

	ret = TPM_WriteTransportLogOut(&ser_ttlo, &ttlo);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = _extend_transdigest(handle, &ser_ttlo);

	return ret;
}


/*
 * Calculate the TPM_TRANSPORT_LOG_IN function that is calculated
 * as part of the TPM_ExecuteTransport ordinal. Extend the TPM_INSTANCE's
 * given transport session's transdigest with the resulting value.
 */
static
uint32_t _calc_login_exec(unsigned char *H1,
                          uint32_t handle) {
	uint32_t ret = 0;
	TPM_TRANSPORT_LOG_IN ttli;
	STACK_TPM_BUFFER(ttli_ser);
	
	ttli.tag = TPM_TAG_TRANSPORT_LOG_IN;
	memcpy(ttli.parameters, H1, sizeof(ttli.parameters));
	
	
	//!!! Only supporting commands with NO handle since it's difficult
	//    to get by the public key
	memset(ttli.pubKeyHash, 0x0, sizeof(ttli.pubKeyHash));
	
	ret = TPM_WriteTransportLogIn(&ttli_ser, &ttli);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = _extend_transdigest(handle, &ttli_ser);
	return ret;
}

/*
 * Calculate the TPM_TRANSPORT_LOG_OUT function that is calculated
 * as part of the TPM_ExecuteTransport ordinal. Extend the TPM_INSTANCE's
 * given transport session's transdigest with the resulting value.
 */
static
uint32_t _calc_logout_exec(unsigned char *H2,
                           TPM_CURRENT_TICKS *currentticks,
                           uint32_t locality,
                           uint32_t handle) {
	uint32_t ret;
	TPM_TRANSPORT_LOG_OUT ttlo;
	STACK_TPM_BUFFER(ttlo_ser);

	ttlo.tag = TPM_TAG_TRANSPORT_LOG_OUT;
	memcpy(ttlo.parameters, H2, sizeof(ttlo.parameters));
	memcpy(&ttlo.currentTicks, currentticks, sizeof(ttlo.currentTicks));
	ttlo.locality = locality;

	ret = TPM_WriteTransportLogOut(&ttlo_ser, &ttlo);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	//printf("logout exec:\n");
	//print_array("ttlo_ser:",ttlo_ser.buffer,ttlo_ser.used);
	ret = _extend_transdigest(handle, &ttlo_ser);

	//char buffer[10];
	//scanf("%s",buffer);
	return ret;
}



/*
 * Calculate the TPM_TRANSPORT_LOG_OUT function that is calculated
 * as part of the TPM_ReleaseTransportSigned ordinal. Extend the TPM_INSTANCE's
 * given transport session's transdigest with the resulting value.
 */
static
uint32_t _calc_logout_release(uint32_t ordinal,
                              uint32_t locality,
                              TPM_CURRENT_TICKS *currentticks,
                              unsigned char *antiReplay,
                              uint32_t handle) {
	uint32_t ret = 0;
	TPM_TRANSPORT_LOG_OUT ttlo;
	STACK_TPM_BUFFER(ttlo_ser);
	STACK_TPM_BUFFER(buffer);

        ret = TSS_buildbuff("L %", &buffer,
	                     ordinal,
			       TPM_NONCE_SIZE, antiReplay);

	ttlo.tag = TPM_TAG_TRANSPORT_LOG_OUT;
	TSS_sha1(buffer.buffer, buffer.used, ttlo.parameters);
	memcpy(&ttlo.currentTicks, currentticks, sizeof(ttlo.currentTicks));
	ttlo.locality = locality;

	ret = TPM_WriteTransportLogOut(&ttlo_ser, &ttlo);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	//printf("logout exec:\n");
	//print_array("ttlo_ser:",ttlo_ser.buffer,ttlo_ser.used);
	ret = _extend_transdigest(handle, &ttlo_ser);

	//char buf[10];
	//scanf("%s",buf);
	return ret;
}


/*
 * Permanently delete the TPM_INSTANCE's given transport session's
 * transdigest by removing its file.
 */
static
uint32_t _delete_transdigest(uint32_t handle) {
	uint32_t ret = 0;
	char *filename = _get_transdigest_file(handle);
	if (filename) {
		unlink(filename);
		free(filename);
	}
	return ret;
}


/*
 * Get the filename of the TPM_INSTANCE's given transport session's
 * current ticks file.
 */
static
char *_get_currentticks_filename(uint32_t handle)
{
	char *filename = malloc(60);
	char *instance = getenv("TPM_INSTANCE");
	int inst;
	if (instance == NULL) {
		instance = "0";
	}
	inst = atoi(instance);
	sprintf(filename,"/tmp/.currentticks-%08x-%d", handle, inst);
	return filename;
}


/*
 * Save the current ticks into the TPM_INSTANCE's given transport
 * session's file
 */
static
uint32_t _save_currentticks(uint32_t handle, TPM_CURRENT_TICKS *tct)
{
	uint32_t ret;
	STACK_TPM_BUFFER(tct_ser);
	FILE *file;
	char *filename = _get_currentticks_filename(handle);
	if (filename == NULL) {
		return ERR_BAD_FILE;
	}

	ret = TPM_WriteCurrentTicks(&tct_ser, tct);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	file = fopen(filename, "w");
	if (file) {
		if (1 != fwrite(tct_ser.buffer, tct_ser.used, 1, file)) {
			ret = ERR_BAD_FILE;
		} else {
			ret = 0;
		}
		if (fclose(file) != 0)
			ret = ERR_BAD_FILE_CLOSE;
	} else {
		ret = ERR_BAD_FILE;
	}
	free(filename);

	return ret;
}


/*
 * Read the current ticks from the TPM_INSTANCE's given transport
 * session's file.
 */
static
uint32_t _read_currentticks(uint32_t handle, TPM_CURRENT_TICKS *tct)
{
	uint32_t ret = 0;
	char *filename = _get_currentticks_filename(handle);
	FILE *file;
	if (filename == NULL) {
		return ERR_BAD_FILE;
	}

	file = fopen(filename, "r");
	if (file != NULL) {
		STACK_TPM_BUFFER(tct_ser);

		tct_ser.used = 32;
		if (1 != fread(tct_ser.buffer, tct_ser.used, 1, file)) {
			ret = ERR_BAD_FILE;
		} else {
			ret = TPM_ReadCurrentTicks(&tct_ser, 0, tct);
			if ((ret & ERR_MASK)) {
				return ret;
			}
			ret = 0;
		}
		fclose(file);
	} else {
		ret = ERR_BAD_FILE;
	}
	free(filename);

	return ret;
}

/*
 * Create the current ticks structure with 'second' and 'microsecond'
 * data taken from the given buffer at the given offset
 */
static
uint32_t _create_currentticks(uint32_t handle,
                              TPM_CURRENT_TICKS *tct,
                              struct tpm_buffer *buffer, uint32_t offset)
{
	uint32_t ret;
	ret = _read_currentticks(handle, tct);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	if (offset + sizeof(uint32_t) + sizeof(uint32_t) > buffer->used) {
		return ERR_BUFFER;
	}

	tct->currentTicks.sec  = LOAD32(buffer->buffer, offset);
	tct->currentTicks.usec = LOAD32(buffer->buffer, offset +
	                                                sizeof(uint32_t));

	ret = 0;
	return ret;
}


/*
 * Delete the TPM_INSTANCE's current ticks file associated with the
 * given transport session (handle).
 */
static
uint32_t _delete_currentticks(uint32_t handle) {
	uint32_t ret = 0;
	char *filename = _get_currentticks_filename(handle);
	if (filename == NULL) {
		return ERR_BAD_FILE;
	}
	unlink(filename);
	free(filename);
	return ret;
}


/*
 * Set the transport function to be used.
 * Once a transport has been set, the transport function
 * will receive the TPM request stream and wrap it in
 * the transport function.
 */
void *TSS_SetTransportFunction(uint32_t (*function)(struct tpm_buffer *tb, 
                                                    const char *msg))
{
	void * old_function = g_transportFunction[0];
	g_transportFunction[0] = function;
	g_num_transports = 1;
	return old_function;
}


/*
 * Add an additional transport function.
 * That function will be called first, unless another transport 
 * function is pushed.
 */
void *TSS_PushTransportFunction(uint32_t (*function)(struct tpm_buffer *tb,
                                                     const char *msg),
				uint32_t *idx)
{
	g_transportFunction[g_num_transports] = function;
	*idx = g_num_transports;
	g_num_transports++;
	return NULL;
}

/*
 * Remove the last transport function from the stack
 * of transports.
 */
void *TSS_PopTransportFunction(uint32_t *idx)
{
	void * oldfunction = NULL;
	if (g_num_transports > 0) {
		g_num_transports--;
		oldfunction = g_transportFunction[g_num_transports];
		*idx = g_num_transports;
	} else {
		*idx = 0;
	}
	return oldfunction;
}

/*
 * Clear all transport function state
 */
void TSS_ClearTransports(void)
{
	g_num_transports = 0;
	g_transportFunction[0] = NULL;
}

/*
 * Set the transport parameters for the transport function
 * that is described in the TPM specs (see below).
 */
uint32_t TSS_SetTransportParameters(session *transSession,
                                    uint32_t idx)
{
	if (idx >= TPM_MAX_TRANSPORTS) {
		return ERR_BAD_ARG;
	}
	g_transSession[idx] = transSession;
	return 0;
}

struct transport_data {
	uint8_t  handles:4;
	uint8_t  rhandles:4;
	uint8_t  flags;
};

enum {
	FLAG_NO_TRANSPORT = 1,
	FLAG_NO_ENCRYPTION = 2,
};



static const struct transport_data td[] = {
	[TPM_ORD_Init]                     = { .flags = FLAG_NO_TRANSPORT },
	[TPM_ORD_Startup]                  = { .handles = 0, },
	[TPM_ORD_SaveState]                = { .handles = 0, },
	[TPM_ORD_SelfTestFull]             = { .handles = 0, },
	[TPM_ORD_ContinueSelfTest]         = { .handles = 0, },
	[TPM_ORD_GetTestResult]            = { .handles = 0, },
	[TPM_ORD_SetOwnerInstall]          = { .handles = 0, },
	[TPM_ORD_OwnerSetDisable]          = { .handles = 0, },
	[TPM_ORD_PhysicalEnable]           = { .handles = 0, },
	[TPM_ORD_PhysicalDisable]          = { .handles = 0, },
	[TPM_ORD_PhysicalSetDeactivated]   = { .handles = 0, },
	[TPM_ORD_SetTempDeactivated]       = { .handles = 0, },
	[TPM_ORD_SetOperatorAuth]          = { .handles = 0, },
	[TPM_ORD_TakeOwnership]            = { .handles = 0, },
	[TPM_ORD_OwnerClear]               = { .handles = 0, },
	[TPM_ORD_ForceClear]               = { .handles = 0, },
	[TPM_ORD_DisableOwnerClear]        = { .handles = 0, },
	[TPM_ORD_DisableForceClear]        = { .handles = 0, },
	[TPM_ORD_GetCapability]            = { .handles = 0, },
	[TPM_ORD_SetCapability]            = { .handles = 0, },
	[TPM_ORD_GetAuditDigest]           = { .handles = 0, },
	[TPM_ORD_GetAuditDigestSigned]     = { .handles = 1, },
	[TPM_ORD_SetOrdinalAuditStatus]    = { .handles = 0, },
	[TPM_ORD_FieldUpgrade]             = { .handles = 0, },
	[TPM_ORD_SetRedirection]           = { .handles = 1, },
	[TPM_ORD_ResetLockValue]           = { .handles = 0, },
	[TPM_ORD_Seal]                     = { .handles = 1, },
	[TPM_ORD_Unseal]                   = { .handles = 1, },
	[TPM_ORD_UnBind]                   = { .handles = 1, },
	[TPM_ORD_CreateWrapKey]            = { .handles = 1, },
	[TPM_ORD_LoadKey2]                 = { .handles = 1, .rhandles = 1 },
	[TPM_ORD_GetPubKey]                = { .handles = 1, },
	[TPM_ORD_Sealx]                    = { .handles = 1, },
	[TPM_ORD_CreateMigrationBlob]      = { .handles = 1, },
	[TPM_ORD_ConvertMigrationBlob]     = { .handles = 1, },
	[TPM_ORD_AuthorizeMigrationKey]    = { .handles = 0, },
	[TPM_ORD_MigrateKey]               = { .handles = 1, },
	[TPM_ORD_CMK_SetRestrictions]      = { .handles = 0, },
	[TPM_ORD_CMK_ApproveMA]            = { .handles = 0, },
	[TPM_ORD_CMK_CreateKey]            = { .handles = 1, },
	[TPM_ORD_CMK_CreateTicket]         = { .handles = 0, },
	[TPM_ORD_CMK_CreateBlob]           = { .handles = 1, },
	[TPM_ORD_CMK_ConvertMigration]     = { .handles = 1, },
	[TPM_ORD_CreateMaintenanceArchive] = { .handles = 0, },
	[TPM_ORD_LoadMaintenanceArchive]   = { .handles = 0, },
	[TPM_ORD_KillMaintenanceFeature]   = { .handles = 0, },
	[TPM_ORD_LoadManuMaintPub]         = { .handles = 0, },
	[TPM_ORD_ReadManuMaintPub]         = { .handles = 0, },
	[TPM_ORD_SHA1Start]                = { .handles = 0, },
	[TPM_ORD_SHA1Update]               = { .handles = 0, },
	[TPM_ORD_SHA1Complete]             = { .handles = 0, },
	[TPM_ORD_SHA1CompleteExtend]       = { .handles = 0, },
	[TPM_ORD_Sign]                     = { .handles = 1, },
	[TPM_ORD_GetRandom]                = { .handles = 0, },
	[TPM_ORD_StirRandom]               = { .handles = 0, },
	[TPM_ORD_CertifyKey]               = { .handles = 2, },
	[TPM_ORD_CertifyKey2]              = { .handles = 2, },
	[TPM_ORD_CreateEndorsementKeyPair] = { .handles = 0, },
	[TPM_ORD_CreateRevocableEK]        = { .handles = 0, },
	[TPM_ORD_RevokeTrust]              = { .handles = 0, },
	[TPM_ORD_ReadPubek]                = { .handles = 0, },
	[TPM_ORD_OwnerReadInternalPub]     = { .handles = 0, },
	[TPM_ORD_MakeIdentity]             = { .handles = 0, },
	[TPM_ORD_ActivateIdentity]         = { .handles = 1, },
	[TPM_ORD_Extend]                   = { .handles = 0, },
	[TPM_ORD_PcrRead]                  = { .handles = 0, },
	[TPM_ORD_Quote]                    = { .handles = 1, },
	[TPM_ORD_PCR_Reset]                = { .handles = 0, },
	[TPM_ORD_Quote2]                   = { .handles = 1, },
	[TPM_ORD_ChangeAuth]               = { .handles = 1, },
	[TPM_ORD_ChangeAuthOwner]          = { .handles = 0, },
	[TPM_ORD_OIAP]                     = { .flags = FLAG_NO_ENCRYPTION },
	[TPM_ORD_OSAP]                     = { .flags = FLAG_NO_ENCRYPTION },
	[TPM_ORD_DSAP]                     = { .flags = FLAG_NO_TRANSPORT },
	[TPM_ORD_SetOwnerPointer]          = { .handles = 0, },
	[TPM_ORD_Delegate_Manage]          = { .handles = 0, },
	[TPM_ORD_Delegate_CreateKeyDelegation]   = { .handles = 1, },
	[TPM_ORD_Delegate_CreateOwnerDelegation] = { .handles = 0, },
	[TPM_ORD_Delegate_LoadOwnerDelegation]   = { .handles = 0, },
	[TPM_ORD_Delegate_ReadTable]             = { .handles = 0, },
	[TPM_ORD_Delegate_UpdateVerification]    = { .handles = 0, },
	[TPM_ORD_Delegate_VerifyDelegation]      = { .handles = 0, },
	[TPM_ORD_NV_DefineSpace]                 = { .handles = 0, },
	[TPM_ORD_NV_WriteValue]                  = { .handles = 0, },
	[TPM_ORD_NV_WriteValueAuth]              = { .handles = 0, },
	[TPM_ORD_NV_ReadValue]                   = { .handles = 0, },
	[TPM_ORD_NV_ReadValueAuth]               = { .handles = 0, },
	[TPM_ORD_KeyControlOwner]                = { .handles = 1, },
	[TPM_ORD_SaveContext]                    = { .handles = 1, },
	[TPM_ORD_LoadContext]                    = { .handles = 1, .rhandles = 1 },
	[TPM_ORD_FlushSpecific]                  = { .handles = 1, },
	[TPM_ORD_GetTicks]                       = { .handles = 0, },
	[TPM_ORD_TickStampBlob]                  = { .handles = 1, },
	[TPM_ORD_EstablishTransport]             = { .handles = 1, 
	                                             .flags = FLAG_NO_TRANSPORT,
	                                             .rhandles = 1, },
	[TPM_ORD_ExecuteTransport]               = { .flags = FLAG_NO_TRANSPORT },
	[TPM_ORD_ReleaseTransportSigned]         = { .handles = 1, 
	                                             .flags = FLAG_NO_TRANSPORT },
	[TPM_ORD_CreateCounter]                  = { .handles = 0, },
	[TPM_ORD_IncrementCounter]               = { .handles = 0, },
	[TPM_ORD_ReadCounter]                    = { .handles = 0, },
	[TPM_ORD_ReleaseCounter]                 = { .handles = 0, },
	[TPM_ORD_ReleaseCounterOwner]            = { .handles = 0, },
	[TPM_ORD_DAA_Join]                       = { .handles = 1, },
	[TPM_ORD_DAA_Sign]                       = { .handles = 1, },
	[TPM_ORD_EvictKey]                       = { .handles = 1, },
	[TPM_ORD_Terminate_Handle]               = { .handles = 1, 
	                                             .flags = FLAG_NO_TRANSPORT },
	[TPM_ORD_SaveKeyContext]                 = { .handles = 1, },
	[TPM_ORD_LoadKeyContext]                 = { .rhandles = 1, },
	[TPM_ORD_SaveAuthContext]                = { .handles = 1,
	/* releases memory */                        /*.flags = FLAG_NO_TRANSPORT*/ },
	[TPM_ORD_LoadAuthContext]                = { .rhandles = 1, },
	[TPM_ORD_DirWriteAuth]                   = { .handles = 0, },
	[TPM_ORD_DirRead]                        = { .handles = 0, },
	[TPM_ORD_ChangeAuthAsymStart]            = { .handles = 1, },
	[TPM_ORD_ChangeAuthAsymFinish]           = { .handles = 2, },
	[TPM_ORD_Reset]                          = { .handles = 0, },
	[TPM_ORD_CertifySelfTest]                = { .handles = 1, },
	[TPM_ORD_OwnerReadPubek]                 = { .handles = 0, },
	[TPM_ORD_DisablePubekRead]               = { .handles = 1, },
	[TPM_ORD_GetCapabilityOwner]             = { .handles = 1, },
	[TPM_ORD_GetCapabilitySigned]            = { .handles = 1, },
	[TPM_ORD_GetOrdinalAuditStatus]          = { .handles = 0, },
	[TPM_ORD_GetAuditEvent]                  = { .handles = 0, },
	[TPM_ORD_GetAuditEventSigned]            = { .handles = 0, },
	[TPM_ORD_LoadKey]                        = { .handles = 1, },
};

#if 0
static const struct transport_data td2[] = {
	[TPM_ORD_CreateInstance]                 = { },
	[TPM_ORD_DeleteInstance]                 = { },
	[TPM_ORD_LockInstance]                   = { },
	[TPM_ORD_GetInstanceData]                = { },
	[TPM_ORD_SetInstanceData]                = { },
	[TPM_ORD_GetInstanceKey]                 = { },
	[TPM_ORD_SetInstanceKey]                 = { },
	[TPM_ORD_TransportInstance]              = { },
	[TPM_ORD_SetupInstance]                  = { },
	[TPM_ORD_UnlockInstance]                 = { },
	[TPM_ORD_GetMigrationDigest]             = { },
};
#endif

int allowsTransport(uint32_t ord)
{
	if (ord <= TPM_ORD_ReleaseTransportSigned)
		return (0 == (td[ord].flags & FLAG_NO_TRANSPORT)); 
#if 0
	if (ord >= TPM_ORD_CreateInstance &&
	    ord <= TPM_ORD_GetMigrationDigest) 
	    	return (0 == (td2[ord].flags & FLAG_NO_TRANSPORT));
#endif
	return 0;
}

uint32_t getNumHandles(uint32_t ord)
{
	if (ord <= TPM_ORD_TickStampBlob)
		return td[ord].handles;
#if 0
	if (ord >= TPM_ORD_CreateInstance &&
	    ord <= TPM_ORD_GetMigrationDigest) 
	    	return td2[ord].handles;
#endif
	return 0;
}

uint32_t getNumRespHandles(uint32_t ord)
{
	if (ord <= TPM_ORD_TickStampBlob)
		return td[ord].rhandles;
#if 0
	if (ord >= TPM_ORD_CreateInstance &&
	    ord <= TPM_ORD_GetMigrationDigest) 
	    	return td2[ord].rhandles;
#endif
	return 0;
}


static uint32_t TPM_EstablishTransport_Internal(uint32_t keyhandle,
                                                unsigned char *usageAuth,
                                                TPM_TRANSPORT_PUBLIC *ttp,
                                                unsigned char *transAuth,
                                                struct tpm_buffer *secret,
                                                TPM_CURRENT_TICKS *currentticks,
                                                session *transSess)
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char transnonce[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_EstablishTransport);
	uint32_t ret;
	uint32_t keyhandle_no = htonl(keyhandle);
	uint32_t encSecretSize_no;
	STACK_TPM_BUFFER(transPub)
	session sess;
	uint32_t transhandle;
	TPM_DIGEST transdigest;
	uint32_t locality;
	TPM_CURRENT_TICKS tct;

	if (NULL == usageAuth ||
	    NULL == ttp ||
	    NULL == secret ) {
		return ERR_NULL_ARG;
	}

	encSecretSize_no  = htonl(secret->used);

	if (keyhandle != TPM_KH_TRANSPORT) {

	       /* generate odd nonce */
		ret  = TSS_gennonce(nonceodd);
		if (0 == ret) return ERR_CRYPT_ERR;

		/* Open OIAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_OIAP|SESSION_DSAP,
		                      &sess,
		                      usageAuth, TPM_ET_KEYHANDLE, keyhandle);
		if (ret != 0)
			return ret;

		/* calculate encrypted authorization value */

		ret = TPM_WriteTransportPublic(&transPub, ttp);
		if ((ret & ERR_MASK)) {
			return ret;
		}
	
		/* move Network byte order data to variable for hmac calculation */
		ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE   , &ordinal_no,
		                   transPub.used  , transPub.buffer,
		                   TPM_U32_SIZE   , &encSecretSize_no,
		                   secret->used   , secret->buffer,
		                   0,0);

		if (0 != ret) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 c2 T l l % @ L % o %", &tpmdata,
		                             ordinal_no,
		                               keyhandle_no,
		                                 transPub.used, transPub.buffer,
		                                   secret->used, secret->buffer,
		                                     TSS_Session_GetHandle(&sess),
		                                       TPM_HASH_SIZE, nonceodd,
		                                         c,
		                                           TPM_HASH_SIZE,authdata);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
	
		if ((ttp->transAttributes & TPM_TRANSPORT_LOG)) {
		        _calc_transdigest(TPM_ORD_EstablishTransport,
			                  ttp,
			                  secret,
			                  &transdigest);
		}

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"EstablishTransport - AUTH1");

		if ((ttp->transAttributes & TPM_TRANSPORT_EXCLUSIVE) == 0)
		        TSS_SessionClose(&sess);

		if (ret != 0) {
			return ret;
		}
		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     TPM_U32_SIZE+32+TPM_NONCE_SIZE, TPM_DATA_OFFSET+TPM_U32_SIZE,
		                     0,0);

		if (0 != ret) {
			return ret;
		}
	} else {
		/* calculate encrypted authorization value */

		ret = TPM_WriteTransportPublic(&transPub, ttp);
		if ((ret & ERR_MASK)) {
			return ret;
		}
	
		/* build the request buffer */
		ret = TSS_buildbuff("00 c1 T l l % @", &tpmdata,
		                             ordinal_no,
		                               keyhandle_no,
		                                 transPub.used, transPub.buffer,
		                                   secret->used, secret->buffer);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
	
		if ((ttp->transAttributes & TPM_TRANSPORT_LOG)) {
		        _calc_transdigest(TPM_ORD_EstablishTransport,
			                  ttp,
			                  secret,
			                  &transdigest);
		}

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"EstablishTransport - AUTH0");

	}

	TPM_ReadCurrentTicks(&tpmdata,
	                     TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_U32_SIZE,
	                     &tct);

	if (NULL != currentticks) {
		memcpy(currentticks, &tct, sizeof(tct));
	}

	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &transhandle);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = tpm_buffer_load32(&tpmdata,
	                        TPM_DATA_OFFSET + TPM_U32_SIZE,
	                        &locality);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	memcpy(transnonce,
	       &tpmdata.buffer[TPM_DATA_OFFSET+TPM_U32_SIZE+TPM_U32_SIZE+32],
	       TPM_NONCE_SIZE);

	TSS_Session_CreateTransport(transSess,
	                            transAuth, transhandle, transnonce);

	if ((ttp->transAttributes & TPM_TRANSPORT_LOG)) {
	        _store_transdigest(transhandle, transdigest);
	        _calc_logout_esttrans(0,
	                              TPM_ORD_EstablishTransport,
	                              locality,
	                              &tct,
	                              transnonce,
	                              transhandle);
	}
	_save_currentticks(transhandle, &tct);

	return 0;
}

uint32_t TPM_EstablishTransport(uint32_t keyhandle,
                                unsigned char *usageAuth,
                                TPM_TRANSPORT_PUBLIC *ttp,
                                unsigned char *transAuth,
                                struct tpm_buffer *secret,
                                TPM_CURRENT_TICKS *currentticks,
                                session *transSess)
{
        uint32_t ret = 0;

        ret = needKeysRoom(keyhandle, 0, 0, 0);
        if (ret != 0)
	        return ret;

        return TPM_EstablishTransport_Internal(keyhandle,
                                               usageAuth,
                                               ttp,
                                               transAuth,
                                               secret,
                                               currentticks,
                                               transSess);
}


uint32_t TPM_EstablishTransport_UseRoom(uint32_t keyhandle,
                                        unsigned char *usageAuth,
                                        TPM_TRANSPORT_PUBLIC *ttp,
                                        unsigned char *transAuth,
                                        struct tpm_buffer *secret,
                                        TPM_CURRENT_TICKS *currentticks,
                                        session *transSess)
{
        uint32_t ret = 0;
        uint32_t replaced_keyhandle = 0;

        // some commands may not call needKeysRoom themselves, so
        // we may replace a key here, which is fine. We just cannot
        // put the original key back in since then the transport
        // will not work.
        ret = needKeysRoom_Stacked(keyhandle, &replaced_keyhandle);
        if (ret != 0)
	        return ret;

        return TPM_EstablishTransport_Internal(keyhandle,
                                               usageAuth,
                                               ttp,
                                               transAuth,
                                               secret,
                                               currentticks,
                                               transSess);
}




void _TPM_getTransportAlgIdEncScheme(TPM_ALGORITHM_ID *algId,
                                     TPM_ENC_SCHEME *encScheme)
{
	char *transpenc = getenv("TPM_TRANSPORT_ENC");
	*algId = 0;
	*encScheme = TPM_ES_NONE;
	
	if (NULL == transpenc) {
        } else if (!strcasecmp(transpenc,"MGF1")) {
		*algId = TPM_ALG_MGF1;
		*encScheme = TPM_ES_NONE;
	} else if (!strcasecmp(transpenc,"OFB")) {
		*algId = TPM_ALG_AES128;
		*encScheme = TPM_ES_SYM_OFB;
	} else if (!strcasecmp(transpenc,"CTR")) {
		*algId = TPM_ALG_AES128;
		*encScheme = TPM_ES_SYM_CTR;
	}
}


static uint32_t encWrappedCommand(struct tpm_buffer *tb, 
                                  struct tpm_buffer *enc,
                                  session *sess,
                                  unsigned char *transNonceOdd,
                                  uint32_t *wrapped_ord,
                                  unsigned char *H1)
{
	uint32_t ret = 0;
	uint8_t handles;
	uint32_t enc_len;
	uint32_t enc_start;
	uint16_t tag;
	uint32_t i;
	STACK_TPM_BUFFER(seed)
	uint32_t tail = 0;
	STACK_TPM_BUFFER(buffer)
	unsigned char *x1 = NULL;

//printf("1. encWrappedCommand!\n");	
	ret = tpm_buffer_load32(tb, 6, wrapped_ord);

	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = tpm_buffer_load16(tb, 0, &tag);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	// !!! need to check the range of wrapped_ord against array
	handles = td[*wrapped_ord].handles;
	if (*wrapped_ord == TPM_ORD_DSAP) {
		enc_start = 2 + 4 + 4 + 2 + 4 + 20 + 4;
	} else {
		enc_start = 2 + 4 + 4 + handles*4;
	}
	enc_len = tb->used;
	enc_len -= enc_start;
	
	switch (tag) {
		case TPM_TAG_RQU_COMMAND:
		break;

		case TPM_TAG_RQU_AUTH1_COMMAND:
			tail = 45;
		break;
	
		case TPM_TAG_RQU_AUTH2_COMMAND:
			tail = 90;
		break;
	}
	enc_len -= tail;

	if ((int)enc_len < 0) {
		return ERR_CRYPT_ERR;
	}

//printf("2. encWrappedCommand!\n");	
	if (enc_len > 0 && 
	    0 == (td[*wrapped_ord].flags & FLAG_NO_ENCRYPTION)) {
	    	TPM_ALGORITHM_ID algId;
	    	TPM_ENC_SCHEME encScheme;
	    	_TPM_getTransportAlgIdEncScheme(&algId, &encScheme);

		if (algId == TPM_ALG_MGF1) {
//printf("Encrypting using MGF1!\n");
			x1 = malloc(enc_len);
			if (NULL == x1) {
				return ERR_MEM_ERR;
			}
			/*
			 * Encrypt MGF1
			 */
			ret = TSS_buildbuff("% % % %", &seed,
			                     TPM_NONCE_SIZE, TSS_Session_GetENonce(sess),
			                       TPM_NONCE_SIZE, transNonceOdd,
			                         sizeof("in")-1, "in",
			                           TPM_HASH_SIZE, TSS_Session_GetAuth(sess));

			if ((ret & ERR_MASK) != 0) {
				goto exit;
			}

			TSS_MGF1(x1,
				 enc_len,
				 seed.buffer,
				 seed.used);
#if 0
{
	int j = 0;
	printf("%s: MGF1: ",__FUNCTION__);
	while (j < 4) {
		printf("%02X ",x1[j++]);
	}
	printf("\n");
}
#endif			

			SET_TPM_BUFFER(enc,tb->buffer,tb->used);
			for (i = 0; i < enc_len; i++) {
				enc->buffer[enc_start+i] = x1[i] ^ tb->buffer[enc_start+i];
			}
		} else if (algId == TPM_ALG_AES128) {
			int rc;
			AES_KEY aeskey;
			unsigned char iv[TPM_AES_BLOCK_SIZE];
			int num;
			ret = TSS_buildbuff("% % %", &seed,
			                     TPM_NONCE_SIZE, TSS_Session_GetENonce(sess),
			                       TPM_NONCE_SIZE, transNonceOdd,
			                         sizeof("in")-1, "in");
			if ((ret & ERR_MASK) != 0) {
				goto exit;
			}
			
			TSS_MGF1(iv,
				 sizeof(iv),
				 seed.buffer,
				 seed.used);
#if 0
{
	int j = 0;
	printf("%s: MGF1: ",__FUNCTION__);
	while (j < 4) {
		printf("%02X ",iv[j++]);
	}
	printf("\n");
}			
#endif
			SET_TPM_BUFFER(enc, tb->buffer, tb->used);
			rc = AES_set_encrypt_key(TSS_Session_GetAuth(sess),
			                         TPM_AES_BITS,
			                         &aeskey);
                        (void)rc;
			num = 0;
			if (encScheme == TPM_ES_SYM_CTR) {
				TPM_AES_ctr128_Encrypt(&enc->buffer[enc_start],	/* out */
						       &tb ->buffer[enc_start],	/* in */
						       enc_len,
						       &aeskey,
						       iv);
			} else {
				AES_ofb128_encrypt(&tb ->buffer[enc_start],
				                   &enc->buffer[enc_start],
				                   enc_len,
				                   &aeskey,
				                   iv,
				                   &num);
			}
		} else {
			SET_TPM_BUFFER(enc,tb->buffer,tb->used);
		} /* if (algId == ... ) ... else ... */
		ret = TSS_buildbuff("L %", &buffer,
		                     *wrapped_ord,
		                       enc_len, &tb->buffer[enc_start]);
	} else {
		SET_TPM_BUFFER(enc,tb->buffer,tb->used);
		ret = TSS_buildbuff("L", &buffer,
		                     *wrapped_ord);
#if 0
printf("NOT ENCRYPTING FOR ORD %X (used=%d,ret=%x).\n",
        *wrapped_ord,
        buffer.used,
        ret);
#endif
	}

	if ((ret & ERR_MASK)) {
		goto exit;
	}

	TSS_sha1(buffer.buffer, buffer.used, H1);

#if 0
{
	uint32_t j = 0;
	printf("H1: ");
	while (j < 4) {
		printf("%02X ",H1[j]);
		j++;
	}
	printf("\n");
}
#endif

	ret = 0;
exit:
	if (x1)
		free(x1);

	return ret;
}


static uint32_t decWrappedCommand(struct tpm_buffer *tb,
                                  uint32_t offset,
                                  struct tpm_buffer *res,
                                  session *sess,
                                  unsigned char *transNonceOdd,
                                  uint32_t wrapped_ord,
                                  unsigned char *H2)
{
	uint32_t ret = 0;
	uint32_t plain;
	uint32_t enc_len;
	unsigned char *x1 = NULL;
	uint32_t i;
	uint16_t tag;
	uint32_t enc_start;
	STACK_TPM_BUFFER(seed)
	uint8_t rhandles;
	STACK_TPM_BUFFER(buffer)
	uint32_t ret_inner = 0;
	uint32_t inner_len;

	ret = tpm_buffer_load32(tb, offset, &inner_len);
	enc_len = inner_len;
	if ((ret & ERR_MASK)) {
		return ret;
	}
	offset += TPM_U32_SIZE;

	ret = tpm_buffer_load16(tb, offset, &tag);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = tpm_buffer_load32(tb, offset + TPM_U16_SIZE + TPM_U32_SIZE, &ret_inner);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	if (ret_inner) {
		SET_TPM_BUFFER(res, &tb->buffer[offset], inner_len);
//printf("Inner return value = %x.\n",ret_inner);
		ret = TSS_buildbuff("L L", &buffer,
		                     ret_inner,
		                       wrapped_ord);
		TSS_sha1(buffer.buffer, buffer.used, H2);
#if 0
{
	uint32_t j = 0;
	printf("H2: ");
	while (j < 4) {
		printf("%02X ",H2[j]);
		j++;
	}
	printf("\n");
}
#endif
		return ret_inner;
	}
	
	switch (tag) {
		case TPM_TAG_RSP_COMMAND:
		break;
		
		case TPM_TAG_RSP_AUTH1_COMMAND:
			enc_len -= 41;
		break;
		
		case TPM_TAG_RSP_AUTH2_COMMAND:
			enc_len -= 82;
		break;
		
		default:
			ret = ERR_BUFFER;
			goto exit;
	}

	if ((int)enc_len < 0) {
		return ERR_CRYPT_ERR;
	}


	if (enc_len > 0 &&
	    0 == (td[wrapped_ord].flags & FLAG_NO_ENCRYPTION) &&
	    wrapped_ord != TPM_ORD_DSAP) {
		TPM_ALGORITHM_ID algId;
		TPM_ENC_SCHEME encScheme;
		_TPM_getTransportAlgIdEncScheme(&algId, &encScheme);

		rhandles = td[wrapped_ord].rhandles;

		plain = 2 + 4 + 4 + 4 * rhandles;
		enc_start = offset + plain;
		enc_len -= plain;

		if (algId == TPM_ALG_MGF1 && (int)enc_len > 0) {
			x1 = malloc(enc_len);
			if (NULL == x1) {
				return ERR_MEM_ERR;
			}
			/*
			 * Encrypt MGF1
			 */
			ret = TSS_buildbuff("% % % %", &seed,
			                     TPM_NONCE_SIZE, TSS_Session_GetENonce(sess),
			                       TPM_NONCE_SIZE, transNonceOdd,
			                         sizeof("out")-1, "out",
			                           TPM_HASH_SIZE, TSS_Session_GetAuth(sess));
			if ((ret & ERR_MASK) != 0) {
				goto exit;
			}

			TSS_MGF1(x1,
				 enc_len,
				 seed.buffer,
				 seed.used);

			SET_TPM_BUFFER(res, &tb->buffer[offset], inner_len);
			for (i = 0 ; i < enc_len; i++) {
				res->buffer[plain+i] = x1[i] ^ tb->buffer[enc_start+i];
			}
		} else if (algId == TPM_ALG_AES128 && (int)enc_len > 0) {
			int rc;
			AES_KEY aeskey;
			unsigned char iv[TPM_AES_BLOCK_SIZE];
			int num;
			ret = TSS_buildbuff("% % %", &seed,
			                     TPM_NONCE_SIZE, TSS_Session_GetENonce(sess),
			                       TPM_NONCE_SIZE, transNonceOdd,
			                         sizeof("out")-1, "out");
			if ((ret & ERR_MASK) != 0) {
				goto exit;
			}

			TSS_MGF1(iv,
				 sizeof(iv),
				 seed.buffer,
				 seed.used);
#if 0
{
	int j = 0;
	printf("%s: MGF1: ",__FUNCTION__);
	while (j < 4) {
		printf("%02X ",iv[j++]);
	}
	printf("\n");
}			
#endif
			SET_TPM_BUFFER(res, &tb->buffer[offset], inner_len);

			rc = AES_set_encrypt_key(TSS_Session_GetAuth(sess),
			                         TPM_AES_BITS,
			                         &aeskey);
                        (void)rc;
			num = 0;
			if (encScheme == TPM_ES_SYM_CTR) {
				TPM_AES_ctr128_Encrypt(&res->buffer[plain],	/* out */
						       &tb ->buffer[enc_start],	/* in */
						       enc_len,
						       &aeskey,
						       iv);
			} else {
				AES_ofb128_encrypt(&tb ->buffer[enc_start],
				                   &res->buffer[plain],
				                   enc_len,
				                   &aeskey,
				                   iv,
				                   &num);
			}
		} else {
			SET_TPM_BUFFER(res, &tb->buffer[offset], inner_len);
		}

		ret = TSS_buildbuff("l L %", &buffer,
		                     ret_inner,
		                       wrapped_ord,
		                         enc_len, &res->buffer[plain]);
	} else {
		SET_TPM_BUFFER(res, &tb->buffer[offset], inner_len);
		ret = TSS_buildbuff("l L", &buffer,
		                     ret_inner,
		                       wrapped_ord);
#if 0
printf("NOT DECRYPTING FOR ORDINAL %X (used=%d,ret=%x).\n",
        wrapped_ord,
        buffer.used,
        ret);
#endif
	}

	if ((ret & ERR_MASK)) {
		goto exit;
	}
	TSS_sha1(buffer.buffer, buffer.used, H2);

#if 0
{
	uint32_t j = 0;
	printf("H2: ");
	while (j < 4) {
		printf("%02X ",H2[j]);
		j++;
	}
	printf("\n");
}
#endif

	ret = 0;
exit:
	if (x1)
		free(x1);

	return ret;
}

static
uint32_t _TPM_ExecuteTransport(struct tpm_buffer *tb,
                               session *transSess,
                               unsigned char * currentTicks,
                               struct tpm_buffer *res,
                               const char *msg)
{
        /* allocate buffer big enough to hold the given data plus 
           some additional 50 bytes */
	ALLOC_TPM_BUFFER(tpmdata,
	                 2+4+4+4+tb->used+50+4+20+1+20);
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	unsigned char H1[TPM_NONCE_SIZE];
	unsigned char *H2;
  	unsigned char c;
	uint32_t ordinal_no = htonl(TPM_ORD_ExecuteTransport);
	uint32_t ret, ret2, rc;
	uint32_t wrappedCommandRetSize_no = htonl(tb->used);
	uint32_t len;
	STACK_TPM_BUFFER(encbuffer);
	uint32_t wrappedOrd;
	char message[1024];
	uint32_t in_ordinal;
	TPM_CURRENT_TICKS currentticks;
	uint32_t locality;

	if (NULL == tpmdata) {
		ret = ERR_MEM_ERR;
		goto exit;
	}

	if (NULL == tb  ||
	    NULL == transSess ||
	    NULL == res ) {
		ret = ERR_NULL_ARG;
		goto exit;
	}
	
	ret = tpm_buffer_load32(tb, 6, &in_ordinal);
	
	sprintf(message,"ExecuteTransport(%s) - AUTH1",msg);

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) {
		ret = ERR_CRYPT_ERR;
		goto exit;
	}

	ret = encWrappedCommand(tb,
	                        &encbuffer,
	                        transSess,
	                        nonceodd,
	                        &wrappedOrd,
	                        H1);
	if ((ret & ERR_MASK)) {
		goto exit;
	}

	_TPM_AuditInputstream(tb,1);
	_calc_login_exec(H1, TSS_Session_GetHandle(transSess));

	/* move Network byte order data to variable for hmac calculation */
	c = 1;
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(transSess),TPM_HASH_SIZE,TSS_Session_GetENonce(transSess),nonceodd,c,
	                   TPM_U32_SIZE      , &ordinal_no,
	                   TPM_U32_SIZE      , &wrappedCommandRetSize_no,
	                   TPM_HASH_SIZE     , H1,
	                   0,0);

	if (0 != ret) {
		goto exit;
	}

	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l @ L % o %", tpmdata,
	                             ordinal_no,
	                               encbuffer.used, encbuffer.buffer,
	                                 TSS_Session_GetHandle(transSess),
	                                   TPM_HASH_SIZE, nonceodd,
	                                     c,
	                                       TPM_HASH_SIZE,authdata);
	if ((ret & ERR_MASK)) {
		goto exit;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(tpmdata,message);
	if (ret != 0) {
		goto exit;
	}
	

	ret = tpm_buffer_load32(tpmdata, TPM_DATA_OFFSET+8, &locality);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	/* check the HMAC in the response */
	ret = tpm_buffer_load32(tpmdata, TPM_DATA_OFFSET+8+4, &len);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	/*
	 * need to get the even nonce from the TPM
	 */
	TSS_Session_SetENonce(transSess,
	                      &tpmdata->buffer[TPM_DATA_OFFSET+8+4+4+len]);


	ret = _create_currentticks(TSS_Session_GetHandle(transSess),
	                           &currentticks, tpmdata, TPM_DATA_OFFSET);
	if ((ret & ERR_MASK)) {
		goto exit;
	}
	/*
	 * I am using an evil trick here for the H2 - I place it behind
	 * the data of the ExecuteTransport command.
	 * That way I don't have to write another checkhmac function.
	 */
	H2 = &tpmdata->buffer[tpmdata->used];
	ret2 = decWrappedCommand(tpmdata,
	                         TPM_DATA_OFFSET+8+4,
	                         res,
	                         transSess,
	                         nonceodd,
	                         wrappedOrd,
	                         &tpmdata->buffer[tpmdata->used]);
	
	_TPM_AuditOutputstream(res, in_ordinal, 1);

	
	ret = TSS_checkhmac1New(tpmdata,ordinal_no,transSess, nonceodd,TSS_Session_GetAuth(transSess),TPM_HASH_SIZE,
	                        8 + 4 + TPM_U32_SIZE  , TPM_DATA_OFFSET,
	                        TPM_HASH_SIZE         , TPM_DATA_OFFSET + 8 + 4 + TPM_U32_SIZE + len + 41, // place of H2 
	                        0,0);

	if (0 != ret || ret2 != 0) {
		goto exit;
	}
	
	if (NULL != currentTicks) {
#if 0
		memcpy(currentTicks,
		       &tpmdata->buffer[TPM_DATA_OFFSET],
		       TPM_CURRENT_TICKS_SIZE);
#endif
	}
	_calc_logout_exec(H2,
	                  &currentticks,
	                  locality,
	                  TSS_Session_GetHandle(transSess));

	/* 
	 * I must get the return code of the inner command now.
	 * The decrypted result is in 'res'.
	 */
	rc = tpm_buffer_load32(res, TPM_RETURN_OFFSET, &ret);
	if ((rc & ERR_MASK)) {
		ret = rc;
	}

exit:
	FREE_TPM_BUFFER(tpmdata);
	return ret;
}

uint32_t TPM_ExecuteTransport(struct tpm_buffer *tb, const char *msg)
{
	uint32_t ret;
	STACK_TPM_BUFFER (result)
	ret = _TPM_ExecuteTransport(tb,
	                            g_transSession[g_num_transports],
	                            NULL,
	                            &result,
	                            msg);
	SET_TPM_BUFFER(tb, result.buffer, result.used);
	return ret;
}


uint32_t TPM_ReleaseTransportSigned(uint32_t keyhandle,
                                    unsigned char * usageAuth,
                                    session *transSess,
                                    unsigned char *antiReplay,
                                    struct tpm_buffer *signature,
                                    unsigned char *transDigest)
{
	uint32_t ret = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_ReleaseTransportSigned);
	unsigned char c = 0;
	uint32_t keyhandle_no = ntohl(keyhandle);
	uint32_t len;

	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char nonceodd2[TPM_NONCE_SIZE];
	unsigned char authdata1[TPM_NONCE_SIZE];
	unsigned char authdata2[TPM_NONCE_SIZE];
	session sess;
	uint32_t locality;
	TPM_CURRENT_TICKS tct;
	uint32_t orig_keyhandle = 0;


	if (NULL == usageAuth  || 
	    NULL == transSess) {
		return ERR_NULL_ARG;
	}
	
	ret = needKeysRoom_Stacked(keyhandle, &orig_keyhandle);
	if (ret != 0)
		return ret;

	TSS_gennonce(nonceodd);
	TSS_gennonce(nonceodd2);

	ret = TSS_SessionOpen(SESSION_DSAP | SESSION_OSAP | SESSION_OIAP,
	                      &sess,
	                      usageAuth, TPM_ET_KEYHANDLE, keyhandle);
	if (0 != ret) {
	        needKeysRoom_Stacked_Undo(keyhandle, orig_keyhandle);
		return ret;
	}

	ret = TSS_authhmac(authdata1,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE , &ordinal_no,
	                   TPM_HASH_SIZE, antiReplay,
	                   0,0);
	if (0 != ret) {
		TSS_SessionClose(&sess);
	        needKeysRoom_Stacked_Undo(keyhandle, orig_keyhandle);
		return ret;
	}

	ret = TSS_authhmac(authdata2,TSS_Session_GetAuth(transSess),TPM_HASH_SIZE,TSS_Session_GetENonce(transSess),nonceodd2,c,
	                   TPM_U32_SIZE, &ordinal_no,
	                   TPM_HASH_SIZE, antiReplay,
	                   0,0);
	if (0 != ret ) {
		TSS_SessionClose(&sess);
	        needKeysRoom_Stacked_Undo(keyhandle, orig_keyhandle);
		return ret;
	}

	ret = TSS_buildbuff("00 c3 T l l % L % o % L % o %", &tpmdata,
	                             ordinal_no,
	                               keyhandle_no  ,
	                                 TPM_HASH_SIZE, antiReplay,
	                                   TSS_Session_GetHandle(&sess),
	                                     TPM_NONCE_SIZE,nonceodd,
	                                       c,
	                                         TPM_HASH_SIZE, authdata1,
	                                           TSS_Session_GetHandle(transSess),
	                                             TPM_NONCE_SIZE,nonceodd2,
	                                               c,
	                                                 TPM_HASH_SIZE,authdata2);

	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		_delete_transdigest(TSS_Session_GetHandle(transSess));
		_delete_currentticks(TSS_Session_GetHandle(transSess));
	        needKeysRoom_Stacked_Undo(keyhandle, orig_keyhandle);
		return ret;
	}

	ret = TPM_Transmit(&tpmdata,"ReleaseTransportSigned - AUTH2");

        /* swap original key back in */
        needKeysRoom_Stacked_Undo(keyhandle, orig_keyhandle);

	TSS_SessionClose(&sess);

	if (0 != ret) {
		_delete_transdigest(TSS_Session_GetHandle(transSess));
		_delete_currentticks(TSS_Session_GetHandle(transSess));
		return ret;
	}
	
	ret = tpm_buffer_load32(&tpmdata, 
	                        TPM_DATA_OFFSET + sizeof(TPM_MODIFIER_INDICATOR) + TPM_CURRENT_TICKS_SIZE, 
	                        &len);

	if ((ret & ERR_MASK)) {
		_delete_transdigest(TSS_Session_GetHandle(transSess));
		_delete_currentticks(TSS_Session_GetHandle(transSess));
		return ret;
	}

	ret = TSS_checkhmac2(&tpmdata,ordinal_no,nonceodd,
	                     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     nonceodd2,
	                     TSS_Session_GetAuth(transSess),TPM_HASH_SIZE,
	                     sizeof(TPM_MODIFIER_INDICATOR) + TPM_CURRENT_TICKS_SIZE + TPM_U32_SIZE + len, TPM_DATA_OFFSET,
	                     0,0);

	ret = tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET, &locality);
	if ((ret & ERR_MASK)) {
		return ret;
	}

	TPM_ReadCurrentTicks(&tpmdata,
	                     TPM_DATA_OFFSET+TPM_U32_SIZE,
	                     &tct);

	if (NULL != signature) {
		SET_TPM_BUFFER(signature,
		               &tpmdata.buffer[TPM_DATA_OFFSET+sizeof(TPM_MODIFIER_INDICATOR)+TPM_CURRENT_TICKS_SIZE+TPM_U32_SIZE],
		               len);
	}

	_calc_logout_release(TPM_ORD_ReleaseTransportSigned,
	                     locality,
	                     &tct,
	                     antiReplay,
	                     TSS_Session_GetHandle(transSess));

	if (transDigest != NULL) {
		_read_transdigest(TSS_Session_GetHandle(transSess),
		                  transDigest);
	}
	//print_array("transDigest: ",transDigest, 20);
	//char buffer[20];
	//scanf("%s",buffer);

	_delete_transdigest(TSS_Session_GetHandle(transSess));
	_delete_currentticks(TSS_Session_GetHandle(transSess));

	return ret;	
}
