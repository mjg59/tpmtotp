/*
 * sealtotp - generate a TOTP secret and seal it to the local TPM
 *
 * Copyright 2015 Matthew Garrett <mjg59@srcf.ucam.org>
 *
 * Copyright 2015 Andreas Fuchs, Fraunhofer SIT
 *
 * Portions derived from sealfile.c by J. Kravitz and Copyright (C) 2004 IBM
 * Corporation
 *
 * Portions derived from qrenc.c Copyright (C) 2006-2012 Kentaro Fukuchi
 * <kentaro@fukuchi.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <qrencode.h>
#include <tss/tspi.h>
#include "base32.h"

#define keylen 20
char key[keylen];
static int margin=1;
static char efivarfs[] = "/sys/firmware/efi/efivars/";

static void writeANSI_margin(FILE* fp, int realwidth,
			     char* buffer, int buffer_s,
			     char* white, int white_s )
{
	int y;

	strncpy(buffer, white, white_s);
	memset(buffer + white_s, ' ', realwidth * 2);
	strcpy(buffer + white_s + realwidth * 2, "\033[0m\n"); // reset to default colors
	for(y=0; y<margin; y++ ){
		fputs(buffer, fp);
	}
}

static int writeANSI(QRcode *qrcode)
{
	FILE *fp;
	unsigned char *row, *p;
	int x, y;
	int realwidth;
	int last, size;

	char *white, *black, *buffer;
	int white_s, black_s, buffer_s;

	white = "\033[47m";
	white_s = 5;
	black = "\033[40m";
	black_s = 5;

	size = 1;

	fp = stdout;

	realwidth = (qrcode->width + margin * 2) * size;
	buffer_s = ( realwidth * white_s ) * 2;
	buffer = (char *)malloc( buffer_s );
	if(buffer == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		exit(1);
	}

	/* top margin */
	writeANSI_margin(fp, realwidth, buffer, buffer_s, white, white_s);

	/* data */
	p = qrcode->data;
	for(y=0; y<qrcode->width; y++) {
		row = (p+(y*qrcode->width));

		bzero( buffer, buffer_s );
		strncpy( buffer, white, white_s );
		for(x=0; x<margin; x++ ){
			strncat( buffer, "  ", 2 );
		}
		last = 0;

		for(x=0; x<qrcode->width; x++) {
			if(*(row+x)&0x1) {
				if( last != 1 ){
					strncat( buffer, black, black_s );
					last = 1;
				}
			} else {
				if( last != 0 ){
					strncat( buffer, white, white_s );
					last = 0;
				}
			}
			strncat( buffer, "  ", 2 );
		}

		if( last != 0 ){
			strncat( buffer, white, white_s );
		}
		for(x=0; x<margin; x++ ){
			strncat( buffer, "  ", 2 );
		}
		strncat( buffer, "\033[0m\n", 5 );
		fputs( buffer, fp );
	}

	/* bottom margin */
	writeANSI_margin(fp, realwidth, buffer, buffer_s, white, white_s);

	fclose(fp);
	free(buffer);

	return 0;
}

int generate_key() {
	int fd = open("/dev/urandom", O_RDONLY);
	int ret;
	if (fd < 0) {
		perror("Unable to open urandom");
		return -1;
	}
	ret = read(fd, key, sizeof(key));
	if (ret != 20) {
		fprintf(stderr, "Unable to read from urandom");
		return -1;
	}
	return 0;
}

int TSPI_SealCurrPCR(TSS_HCONTEXT c, uint32_t keyhandle, uint32_t pcrmap,
			 unsigned char *keyauth,
			 unsigned char *dataauth,
			 unsigned char *data, unsigned int datalen,
			 unsigned char *blob, unsigned int *bloblen)
{
#define CHECK_ERROR(r,m) if (r != TSS_SUCCESS) { fprintf(stderr, m ": 0x%08x\n", r); return -1;}

	TSS_RESULT r = 0;
	TSS_HTPM tpm;
	TSS_HPCRS pcrComposite;
	TSS_UUID uuid;
	TSS_UUID srk_uuid = TSS_UUID_SRK;
	TSS_HKEY key;
	TSS_HENCDATA seal;
	TSS_HPOLICY key_policy, seal_policy;
	unsigned char *cipher;
	unsigned int cipher_len;

	/* Get the PCR values into composite object */
	r = Tspi_Context_GetTpmObject(c, &tpm);
	CHECK_ERROR(r, "Error Getting TPM");
	r = Tspi_Context_CreateObject(c, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO_LONG, &pcrComposite);
	CHECK_ERROR(r, "Error Creating PCR-Composite");
	r = Tspi_PcrComposite_SetPcrLocality(pcrComposite, TPM_LOC_ZERO | TPM_LOC_ONE |
				TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR);
	CHECK_ERROR(r, "Error Setting Localities");

	for (uint32_t pcrmask = 1, pcr = 0; pcr < 24; pcr++, pcrmask <<= 1) {
		if ((pcrmap & pcrmask) != 0) {
			uint32_t pcrval_size;
			uint8_t *pcrval;
			r = Tspi_TPM_PcrRead(tpm, pcr, &pcrval_size, &pcrval);
			CHECK_ERROR(r, "Error Reading PCR");
			r = Tspi_PcrComposite_SetPcrValue(pcrComposite, pcr, pcrval_size, pcrval);
			CHECK_ERROR(r, "Error Setting Composite");
			r = Tspi_Context_FreeMemory(c, pcrval);
			CHECK_ERROR(r, "Error Freeing Memory");
		}
	}

	/* Get the SRK and Policy Ready */
	if (keyhandle = 0x40000000) {
		uuid = srk_uuid;
	} else {
		fprintf(stderr, "Error, only SRK currently supported\n");
		r = 1;
		return -1;
	}
	r = Tspi_Context_LoadKeyByUUID(c, TSS_PS_TYPE_SYSTEM, uuid, &key);
	CHECK_ERROR(r, "Error Loading Key");
	r = Tspi_Context_CreateObject(c, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &key_policy);
	CHECK_ERROR(r, "Error Creating Policy");
	r = Tspi_Policy_SetSecret(key_policy, TSS_SECRET_MODE_SHA1, keylen, keyauth);
	CHECK_ERROR(r, "Error Setting Secret");
	r = Tspi_Policy_AssignToObject(key_policy, key);
	CHECK_ERROR(r, "Error Assigning Policy");

	/* Get the Encdata Ready */
	r = Tspi_Context_CreateObject(c, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &seal);
	CHECK_ERROR(r, "Error Creating EncData");
	r = Tspi_Context_CreateObject(c, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &seal_policy);
	CHECK_ERROR(r, "Error Creating Policy");
	r = Tspi_Policy_SetSecret(seal_policy, TSS_SECRET_MODE_SHA1, keylen, dataauth);
	CHECK_ERROR(r, "Error Setting Secret");
	r = Tspi_Policy_AssignToObject(seal_policy, seal);
	CHECK_ERROR(r, "Error Assigning Policy");

	/* Seal the Data */
	r = Tspi_Data_Seal(seal, key, datalen, data, pcrComposite);
	CHECK_ERROR(r, "Error Sealing Data");
	r = Tspi_GetAttribData(seal, TSS_TSPATTRIB_ENCDATA_BLOB,
                                   TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                   &cipher_len, &cipher);
	CHECK_ERROR(r, "Error Getting Sealed Data");

	/* Return that stuff */
	if (cipher_len > bloblen) {
		sprintf(stderr, "Internal Error, cipher too long");
		r = 1;
		return -1;
	}
	memcpy(blob, cipher, cipher_len);
	*bloblen = cipher_len;

	/* Note: Do not even bother to return cipher directly. Would be freed during Context_Close anyways */
	Tspi_Context_FreeMemory(c, cipher);

	return (r == 0)? 0 : -1;
}

int main(int argc, char *argv[])
{
	int ret;
	char base32_key[BASE32_LEN(keylen)+1];
	unsigned char uefiblob[4100];
	unsigned char blob[4096];	/* resulting sealed blob */
	unsigned int bloblen;	/* blob length */
	unsigned char wellknown[20] = {0};
	unsigned char totpstring[64];
	FILE *infile;
	FILE *outfile;
	QRcode *qrcode;
	TSS_HCONTEXT c;

	if (generate_key()) {
		return -1;
	}
	base32_encode(key, keylen, base32_key);
	base32_key[BASE32_LEN(keylen)] = NULL;

	ret = Tspi_Context_Create(&c);
	if (ret != TSS_SUCCESS) {
		fprintf(stderr, "Unable to create TPM context\n");
		return -1;
	}
	ret = Tspi_Context_Connect(c, NULL);
	if (ret != TSS_SUCCESS) {
		fprintf(stderr, "Unable to connect to TPM\n");
		return -1;
	}
	ret = TSPI_SealCurrPCR(c, // context
			      0x40000000, // SRK
			      0x000000BF, // PCRs 0-5 and 7
			      wellknown,  // Well-known SRK secret
			      wellknown,  // Well-known SEAL secret
			      key, keylen,	/* data to be sealed */
			      blob, &bloblen);	/* buffer to receive result */
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_Seal\n",
			TPM_GetErrMsg(ret));
		goto out;
	}

	sprintf(totpstring, "otpauth://totp/TPMTOTP?secret=%s", base32_key);
	qrcode = QRcode_encodeString(totpstring, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
	writeANSI(qrcode);

	if (strncmp(argv[1], "-n", 2) == 0) {
		TSS_HNVSTORE nvObject;
		TSS_FLAG nvattrs = 0;

		ret = Tspi_Context_CreateObject(c, TSS_OBJECT_TYPE_NV,
						nvattrs, &nvObject);
		if (ret != TSS_SUCCESS) {
			fprintf(stderr, "Unable to create nvram object: %x\n",
				ret);
			goto out;
		}
		ret = Tspi_SetAttribUint32(nvObject, TSS_TSPATTRIB_NV_INDEX, 0,
					   0x10004d47);
		if (ret != TSS_SUCCESS) {
			fprintf(stderr, "Unable to set index\n");
			goto out;
		}
		ret = Tspi_SetAttribUint32(nvObject,
					   TSS_TSPATTRIB_NV_PERMISSIONS, 0,
				   TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE);
		if (ret != TSS_SUCCESS) {
			fprintf(stderr, "Unable to set permissions\n");
			goto out;
		}
		ret = Tspi_SetAttribUint32(nvObject, TSS_TSPATTRIB_NV_DATASIZE,
					   0, bloblen);
		if (ret != TSS_SUCCESS) {
			fprintf(stderr, "Unable to set size\n");
			goto out;
		}
		ret = Tspi_NV_DefineSpace(nvObject, NULL, NULL);
		if (ret != TSS_SUCCESS && ret != (0x3000 | TSS_E_NV_AREA_EXIST)) {
			fprintf(stderr, "Unable to define space: %x\n", ret);
			goto out;
		}
		ret = Tspi_NV_WriteValue(nvObject, 0, bloblen, blob);
		if (ret != TSS_SUCCESS) {
			fprintf(stderr, "Unable to write to nvram\n");
			goto out;
		}
	} else {
		outfile = fopen(argv[1], "w");
		if (outfile == NULL) {
			fprintf(stderr, "Unable to open output file '%s'\n",
				argv[1]);
			goto out;
		}
		if (strncmp(argv[1], efivarfs, strlen(efivarfs)) == 0) {
			int attributes = 7; // NV, RT, BS
			memcpy(uefiblob, &attributes, sizeof(int));
			memcpy(uefiblob + sizeof(int), blob, bloblen);
			bloblen += sizeof(int);
			ret = fwrite(uefiblob, 1, bloblen, outfile);
		} else {
			ret = fwrite(blob, 1, bloblen, outfile);
		}
		if (ret != bloblen) {
			fprintf(stderr,
				"I/O Error while writing output file '%s'\n",
				argv[1]);
			goto out;
		}
		fclose(outfile);
	}

out:
	Tspi_Context_FreeMemory(c, NULL);
	Tspi_Context_Close(c);

	exit(ret);
}
