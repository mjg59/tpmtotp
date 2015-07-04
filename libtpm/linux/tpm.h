/*
 * include/linux/tpm.h 
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef _LINUX_TPM_H
#define _LINUX_TPM_H

#include <linux/ioctl.h>

/* ioctl commands */
#define	TPMIOC_CANCEL		_IO('T', 0x00)
#define	TPMIOC_TRANSMIT		_IO('T', 0x01)

#if defined(__KERNEL__)
extern ssize_t tpm_transmit(const char *buf, size_t bufsiz);
extern ssize_t tpm_extend(int index, u8 *digest);
extern ssize_t tpm_pcrread(int index, u8 *hash);
extern ssize_t tpm_dirread(int index, u8 *hash);
extern ssize_t tpm_cap_version(int *maj, int *min, int *ver, int *rev);
extern ssize_t tpm_cap_pcr(int *pcrs);
extern ssize_t tpm_cap_dir(int *dirs);
extern ssize_t tpm_cap_manufacturer(int *manufacturer);
extern ssize_t tpm_cap_slot(int *slots);
#endif /* __KERNEL__ */

#endif /* _LINUX_TPM_H */
