/*
 * libtpm: tpmutil.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef TPMUTIL_H
#define TPMUTIL_H

#include <stdint.h>

uint32_t TSS_getsize(unsigned char *rsp);
int TSS_gennonce(unsigned char *nonce);
uint32_t TSS_buildbuff(char *format, unsigned char *buffer, ...);
uint32_t TPM_Transmit(unsigned char *buff, char *msg);
int TPM_setlog(int flag);
void TSS_sha1(unsigned char *input, int len, unsigned char *output);
uint32_t TPM_GetRandom(unsigned char *buf);
#endif
