/*
 * libtpm: pcrs.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef PCRS_H
#define PCRS_H

#define TPM_PCR_NUM       16	/* number of PCR registers supported */
#define TPM_PCR_MASK_SIZE  2	/* size in bytes of PCR bit mask     */

uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue);
uint32_t TSS_GenPCRInfo(uint32_t pcrmap, unsigned char *pcrinfo,
			unsigned int *len);

#endif
