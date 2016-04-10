/********************************************************************************/
/*										*/
/*			     	TPM Low Level Transport				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpm_lowlevel.h 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#ifndef TPM_LOWLEVEL_H
#define TPM_LOWLEVEL_H

#include "tpm.h"

struct tpm_transport 
{
  uint32_t (*open)(int *fd);
  uint32_t (*close)(int fd);
  uint32_t (*send)(int fd, struct tpm_buffer *tb, const char *msg);
  uint32_t (*recv)(int fd, struct tpm_buffer *tb);
};

enum {
    TPM_LOWLEVEL_TRANSPORT_CHARDEV = 1,
    TPM_LOWLEVEL_TRANSPORT_TCP_SOCKET,
    TPM_LOWLEVEL_TRANSPORT_UNIXIO,
    TPM_LOWLEVEL_TRANSPORT_CCA,
    TPM_LOWLEVEL_TRANSPORT_LIBTPMS,
};

void TPM_LowLevel_TransportSocket_Set(void);
void TPM_LowLevel_TransportUnixIO_Set(void);
void TPM_LowLevel_TransportCharDev_Set(void);
#ifdef TPM_USE_LIBTPMS
void TPM_LowLevel_TransportLibTPMS_Set(void);
#endif
struct tpm_transport *TPM_LowLevel_Transport_Set(struct tpm_transport *new_tp);
int TPM_LowLevel_Transport_Init(int choice);
int TPM_LowLevel_Use_VTPM(void);
int TPM_LowLevel_VTPM_Set(int state);

#endif
