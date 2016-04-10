/********************************************************************************/
/*										*/
/*			     	TPM Key Swapping Routines			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: keyswap.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <unistd.h>
#include <assert.h>

#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"
#include "tpm_constants.h"
#include "tpmutil.h"
#include "tpm_error.h"
#include "tpm_lowlevel.h"

extern uint32_t g_num_transports;

static int IsKeyInTPM(struct tpm_buffer *capabilities, uint32_t shandle);


static char *createKeyFilename(uint32_t keyhandle)
{
	char buffer[200];
	char *inst = getenv("TPM_INSTANCE");
	sprintf(buffer,"/tmp/.key-%08X-%s",keyhandle,inst);
	return strdup(buffer);
}

static int isKeySwapable(uint32_t shandle)
{
	if (shandle == 0x00000000 ||
	    (shandle >= TPM_KH_SRK &&
	     shandle <= TPM_KH_EK) ||
	    shandle == 0xffffffff) {
		return 0;
	}
	return 1;
}

static uint32_t swapOutKey(uint32_t handle)
{	
	unsigned char labelhash[20];
	char *filename = createKeyFilename(handle);
	STACK_TPM_BUFFER(context);
	uint32_t ret = 0;

	if (NULL == filename) {
		ret = ERR_MEM_ERR;
	}

#if 0
	printf("Swapping OUT key with handle %08x\n",handle);
#endif
	
	TSS_sha1("KEY",3,labelhash);


	if (ret == 0) {
		ret = TPM_SaveContext_UseRoom(handle,
		                              TPM_RT_KEY,
		                              (char *)labelhash,
		                              &context);
	}

	if (ret == 0) {
		FILE * f = fopen(filename, "w+");
		if (f) {
			fwrite(context.buffer, context.used, 1, f);
			if (fclose(f) != 0)
				ret = ERR_BAD_FILE_CLOSE;
		} else {
			ret = ERR_BAD_FILE;
		}
	}
	
	if (ret == 0) {
		/*ret =*/ TPM_EvictKey_UseRoom(handle);
#if 0
		printf("Evicted key with handle 0x%08x\n",handle);
	} else {
		printf("DID NOT Evicted key with handle 0x%08x\n",handle);
#endif
	}

#if 0
	if (ret == 0) {
		printf("Swapped out key with handle %08x.\n",handle);
	} else {
		printf("Could NOT swap out key with handle %08x.\n",handle);
	}
#endif
	
	return ret;
}


static uint32_t swapInKey(uint32_t handle)
{	
	char *filename = createKeyFilename(handle);
	STACK_TPM_BUFFER(context);
	unsigned char * mycontext = NULL;
	uint32_t contextSize;
	uint32_t newhandle;
	uint32_t ret;

	if (NULL == filename) {
		ret = ERR_MEM_ERR;
	}
	
	ret = TPM_ReadFile(filename,&mycontext,&contextSize);
	if ((ret & ERR_MASK)) {
#if 0
		printf("level: %d\n",g_num_transports);
#endif
#if 0
		fprintf(stderr,"Could not read from keyfile %s.\n",filename);
#endif
		return ret;
	}
	SET_TPM_BUFFER(&context, mycontext, contextSize);
	free(mycontext);
	
	ret = TPM_LoadContext(handle,
		              1,
		              &context,
		              &newhandle);

	if (ret != 0) {
		printf("Got error '%s' while swapping in key 0x%08x.\n",
		       TPM_GetErrMsg(ret),
		       handle);
	}
	if (handle != newhandle) {
		printf("keyswap: "
		       "new handle 0x%08x not the same as old one 0x%08x.\n",
		       newhandle, handle);
	}
	if (ret == 0) {
		unlink(filename);
	}
	free(filename);
#if 0
	if (ret == 0) {
		fprintf(stderr, "SWAP IN Swapped in key with handle %08x.\n",handle);
	} else {
		fprintf(stderr, "Could NOT swap in key with handle %08x.\n",handle);
	}
#endif
	
	return ret;
}


static uint32_t swapOutKeys(uint32_t neededslots,
                            uint32_t key1, uint32_t key2, uint32_t key3,
                            struct tpm_buffer *capabilities,
                            uint32_t *orig_key1)
{
	uint32_t ret = 0;
	uint32_t ctr;
	uint32_t handle;

#if 0
        fprintf(stderr,"%s: neededslots: %d\n", __FUNCTION__,neededslots);
#endif
	if (orig_key1)
	        *orig_key1 = 0;

#if 0
	fprintf(stderr,"must keep keys %08x %08x %08x   room=%d\n",
	        key1,key2,key3,neededslots);
#endif
	ctr = 2;

	while (ctr < capabilities->used) {
		tpm_buffer_load32(capabilities,
		                  ctr,
		                  &handle);

		if (handle != key1 &&
		    handle != key2 &&
		    handle != key3) {
		    	ret = swapOutKey(handle);
		        if (ret == 0 && orig_key1 && *orig_key1 == 0) {
		                *orig_key1 = handle;
                        }
                        if (ret == 0) {
                                neededslots--;
                                if (neededslots == 0)
                                        break;
                        }
#if 0
	                if (ret == 0)
	                        fprintf(stderr,"SWAPPED OUT KEY = 0x%08x\n", handle);
                        if (ret == TPM_OWNER_CONTROL)
                                fprintf(stderr,"KEY UNDER OWNER CONTROL = 0x%08x\n", handle);
#endif
		}


		if (ret != 0 && ret != TPM_OWNER_CONTROL) {
			break;
		}

		ctr += sizeof(handle);
	}

	if (ret == TPM_OWNER_CONTROL)
		ret = 0;

	return ret;
}

/*
 * Check whether a key is in the TPM. Returns the index (>=0) at which
 * slot the key is, -1 otherwise.
 */
static int IsKeyInTPM(struct tpm_buffer *capabilities, uint32_t shandle)
{
	uint32_t ctr;
	int rc = 0;
	uint32_t handle;

	if (shandle == 0x00000000 ||
	    (shandle >= TPM_KH_SRK &&
	     shandle <= TPM_KH_EK) ||
	    shandle == 0xffffffff) {
		return 1;
	}

	for (ctr = 2; ctr < capabilities->used; ctr += sizeof(handle)) {
		tpm_buffer_load32(capabilities,
		                  ctr,
		                  &handle);

		if (handle == shandle) {
			rc = 1;
			break;
		}
	}
	
#if 0
	if (rc == 1) {
		printf("key %08x is in TPM\n",shandle);
	} else {
		printf("key %08x is NOT in TPM\n", shandle);
	}
#endif
	return rc;
}



/* 
 * make sure the given keys are in the TPM and there is
 * enough room for 'room' keys in the TPM
 */
static uint32_t
needKeysRoom_General(uint32_t key1, uint32_t key2, uint32_t key3,
                     uint32_t room,
                     uint32_t *orig_key1)
{
	uint32_t ret = 0;
	uint32_t scap_no;
	STACK_TPM_BUFFER(context);
	STACK_TPM_BUFFER(scap);
	STACK_TPM_BUFFER(capabilities);
	uint32_t tpmkeyroom;
	uint32_t keysintpm;
	int intpm1, intpm2, intpm3;
	uint32_t neededslots;
	char *tmp1;
	char *tmp2;
	char *tmp3;
	
	tmp1 = getenv("TPM_AUDITING");
	tmp2 = getenv("TPM_TRANSPORT");
	tmp3 = getenv("TPM_NO_KEY_SWAP");

	if ((tmp1 && !strcmp(tmp1,"1") && 
	     tmp2 && !strcmp(tmp2,"1")) ||
	    (tmp3 && !strcmp(tmp3,"1")) ) {
		return 0;
	}
	
#if 0
	printf("level: %d\n",g_num_transports);
#endif
	/*
	 * Support for 1.1 TPMs is not possible since the key handle
	 * must be maintained and the old SaveKeyContext functions don't
	 * do that.
	 *
	 * Strategy for 1.2 TPMs:
         *  Check the number of keys the TPM can handle.
         *  Check which keys are in the TPM and how many.
         *  If there's enough room for all keys that need to be loaded in,
         *   just load them in, otherwise swap an unneeded key out first.
         *  If necessary, swap as many keys out such that there's enough
         *  room for 'room' keys.
	 */
	
	scap_no = htonl(TPM_CAP_PROP_MAX_KEYS);   // 0x110
	SET_TPM_BUFFER(&scap, &scap_no, sizeof(scap_no));
	ret = TPM_GetCapability_NoTransport(TPM_CAP_PROPERTY, // 0x5
	                                    &scap,
	                                    &capabilities);
	if (ret != 0) {
		/* call may fail at very beginning */
		return 0;
	} else {
		ret = tpm_buffer_load32(&capabilities, 0, &tpmkeyroom);
		if (ret != 0) {
			return ret;
		}
	}


	scap_no = ntohl(TPM_RT_KEY);
	SET_TPM_BUFFER(&scap, &scap_no, sizeof(scap_no));
	ret = TPM_GetCapability_NoTransport(TPM_CAP_KEY_HANDLE,
	                                    &scap,
	                                    &capabilities);
	if (ret != 0) {
		printf("Error %s from TPM_GetCapability.\n",
		       TPM_GetErrMsg(ret));
		return ret;
	}

	neededslots = room;
	
	intpm1 = IsKeyInTPM(&capabilities, key1);
	if (!intpm1)
		neededslots++;
	intpm2 = IsKeyInTPM(&capabilities, key2);
	if (!intpm2)
		neededslots++;
	intpm3 = IsKeyInTPM(&capabilities, key3);
	if (!intpm3)
		neededslots++;

#if 0
	uint32_t ctr, handle;
	for (ctr = 2; ctr < capabilities.used; ctr += sizeof(handle)) {
		ret = tpm_buffer_load32(&capabilities,
		                        ctr,
		                        &handle);
		if (ret != 0) {
			break;
		}
		printf("available key: %08x\n",handle);
	}
#endif

	keysintpm = (capabilities.used - 2 ) / 4;

#if 0
	fprintf(stderr,"TPM has room for %d keys, holds %d keys. need %d slots\n",
	        tpmkeyroom,keysintpm, neededslots);
#endif

        assert(neededslots <= tpmkeyroom);

	if ((int)neededslots > ((int)tpmkeyroom - (int)keysintpm)) {
		ret = swapOutKeys((int)neededslots - ((int)tpmkeyroom-(int)keysintpm),
		                  key1,
		                  key2,
		                  key3,
		                  &capabilities,
		                  orig_key1);
#if 0
	} else {
		printf("No need to swap out keys.\n");
#endif
	}

	if (ret == 0 && !intpm1) {
		ret = swapInKey(key1);
	}
	if (ret == 0 && !intpm2) {
		ret = swapInKey(key2);
	}
	if (ret == 0 && !intpm3) {
		ret = swapInKey(key3);
	}

	return ret;
}

/* 
 * make sure the given keys are in the TPM and there is
 * enough room for 'room' keys in the TPM
 *
 * For all general functions, except for those that can be
 * stacked (transport-related, virtual TPM transport instance
 * related) I reserve '1' more key slots for every stacked layer.
 * This is necessary so that once for example the Transport functions
 * are called and want to swap their own keys in, that they don't 
 * swap keys out that are currently needed.
 */
uint32_t needKeysRoom(uint32_t key1, uint32_t key2, uint32_t key3,
                      int room)
{
        char *trans = getenv("TPM_TRANSPORT");
        uint32_t transport = 0;
        /* g_num_transport likely always 0 */
        uint32_t rm;

        if (trans && !strcmp("1", trans))
            transport = 1;

        rm = room + g_num_transports + 2 + transport;
        if (room < 0)
                rm = 0;
        else {
                if (key1)
                        rm--;
                if (key2)
                        rm--;
                if (key3)
                        rm--;
        }
	return needKeysRoom_General(key1,
	                            key2,
	                            key3,
	                            rm,
	                            NULL);
}

uint32_t needKeysRoom_Stacked(uint32_t key1, uint32_t *orig_key1)
{
	return needKeysRoom_General(key1,
	                            0,
	                            0,
	                            0,
	                            orig_key1);
}

uint32_t needKeysRoom_Stacked_Undo(uint32_t swapout_key, uint32_t swapin_key)
{
        uint32_t ret;
        int swapped = 0;

        if (isKeySwapable(swapout_key)) {
                ret = swapOutKey(swapout_key);
                if (ret != 0)
                        return ret;
                swapped = 1;
        }

	return needKeysRoom_General(swapin_key,
	                            0,
	                            0,
	                            (swapped) ? 0 : 1,
	                            NULL);
}
