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
#include "tpmfunc.h"
#include "base32.h"
#include <tss/tspi.h>

#define keylen 20
char key[keylen];
static int margin=1;
static char efivarfs[] = "/sys/firmware/efi/efivars/";

#define LEN 20
#define NUM_PCRS 24
static uint8_t **pcrvals;

#define CHECK_MALLOC(res) if (res == NULL) { fprintf(stderr, "Failed to allocate memory.\n"); exit(EXIT_FAILURE); }

void print_help()
{
	char *help = "Usage: sealtotop [OPTION]... OUTFILE\n"
		"  -h, --help: Print this help.\n"
		"  -n, --no-qrcode: Don't print the secret as QR code.\n"
		"  -b, --base32: Print the secret as a base32 string.\n"
		"  -p, --pcrs: A comma-separated list of PCRs to use. Use n=X to manually set the value \n"
		"              of PCR n to X, where X is the hex representation of the desired value.\n"
		"              Default: 1,2,3,4,5,7.\n"
		"              The hex representation may contain spaces between the bytes like XX XX.";

	printf("%s", help);

}

void convert_hex_to_bytes(char *hex_vals, uint8_t* res)
{

	int i = 0;
	unsigned int tmp = 0;

	for (i = 0; i < LEN; i++) {
		sscanf(hex_vals + 2*i, "%02x", &tmp);
		res[i] = (uint8_t)tmp;
	}
}


unsigned int parse_pcrs(char *optarg)
{
	uint32_t pcrflag = 0;
	char *token = strtok(optarg, ",");

	while (token != NULL) {

		unsigned int num = (unsigned int)strtol(token, NULL, 10);

		if (num >= NUM_PCRS) {
			fprintf(stderr, "Invalid PCR number: %u. Must be between 0 and %u.\n",
				num, NUM_PCRS-1);
			exit(EXIT_FAILURE);
		}

		pcrflag |= (1 << num);

		char *val = strchr(token, '=');
		uint8_t *res = NULL;


		if (val != NULL) { // PCR value supplied
			val+=1; // ignore delimiter

			res = malloc(LEN * sizeof(uint8_t));
			CHECK_MALLOC(res);

			if (strlen(val) == LEN*2)  // no spaces
				convert_hex_to_bytes(val, res);

			else if (strlen(val) == LEN*3-1) { // spaces between each byte (like FF FF), remove them.
				char *tmp = malloc(2*LEN*sizeof(uint8_t));
				CHECK_MALLOC(tmp);

				int i = 0;
				int j = 0;

				for (i = 0; i < strlen(val); i++) {
					if (val[i] != ' ')
						tmp[j++] = val[i];
				}

				if (j != LEN*2) {
					fprintf(stdout, "Invalid format for PCR %u\n", num);
					free(res);
					exit(EXIT_FAILURE);
				}
				else {
					convert_hex_to_bytes(tmp, res);
				}

				free(tmp);

			} else { // invalid string
				fprintf(stdout, "Invalid format for PCR %u\n", num);
				exit(EXIT_FAILURE);
			}

		}

		pcrvals[num] = res;
		token = strtok(NULL, ",");

	}
	return pcrflag;
}


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
		exit(EXIT_FAILURE);
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

int TSPI_SealCurrPCR(uint32_t keyhandle, uint32_t pcrmap,
			 unsigned char *keyauth,
			 unsigned char *dataauth,
			 unsigned char *data, unsigned int datalen,
			 unsigned char *blob, unsigned int *bloblen)
{
#define CHECK_ERROR(r,m) if (r != TSS_SUCCESS) { fprintf(stderr, m ": 0x%08x\n", r); goto close_ret; }

	TSS_RESULT r = 0;
	TSS_HCONTEXT c;
	TSS_HTPM tpm;
	TSS_HPCRS pcrComposite;
	TSS_UUID uuid;
	TSS_UUID srk_uuid = TSS_UUID_SRK;
	TSS_HKEY key;
	TSS_HENCDATA seal;
	TSS_HPOLICY key_policy, seal_policy;
	unsigned char *cipher;
	unsigned int cipher_len;

	/* Get ourselfs a 1.2 context object connected to tcsd */
	r = Tspi_Context_Create(&c);
	if (r != TSS_SUCCESS) {
		fprintf(stderr, "Error Creating Context\n");
		return -1;
	}
	r = Tspi_Context_Connect(c, NULL);
	CHECK_ERROR(r, "Error Connecting Context");

	/* Get the PCR values into composite object */
	r = Tspi_Context_GetTpmObject(c, &tpm);
	CHECK_ERROR(r, "Error Getting TPM");
	r = Tspi_Context_CreateObject(c, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO_LONG, &pcrComposite);
	CHECK_ERROR(r, "Error Creating PCR-Composite");
	r = Tspi_PcrComposite_SetPcrLocality(pcrComposite, TPM_LOC_ZERO | TPM_LOC_ONE |
				TPM_LOC_TWO | TPM_LOC_THREE | TPM_LOC_FOUR);
	CHECK_ERROR(r, "Error Setting Localities");

	for (uint32_t pcrmask = 1, pcr = 0; pcr < NUM_PCRS; pcr++, pcrmask <<= 1) {
		if ((pcrmap & pcrmask) != 0) {
			uint32_t pcrval_size;
			uint8_t *pcrval;
			if (pcrvals[pcr] == NULL) {
			     r = Tspi_TPM_PcrRead(tpm, pcr, &pcrval_size, &pcrval);
			     CHECK_ERROR(r, "Error Reading PCR");
			     r = Tspi_PcrComposite_SetPcrValue(pcrComposite, pcr, pcrval_size, pcrval);
			     CHECK_ERROR(r, "Error Setting Composite");
			     r = Tspi_Context_FreeMemory(c, pcrval);
			     CHECK_ERROR(r, "Error Freeing Memory");
			}
			else {
			     pcrval = pcrvals[pcr];
			     r = Tspi_PcrComposite_SetPcrValue(pcrComposite, pcr, LEN, pcrval);
			     CHECK_ERROR(r, "Error Setting Composite");
			}
		}
	}

	/* Get the SRK and Policy Ready */
	if (keyhandle = 0x40000000) {
		uuid = srk_uuid;
	} else {
		fprintf(stderr, "Error, only SRK currently supported\n");
		r = 1;
		goto close_ret;
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
		goto close_ret;
	}
	memcpy(blob, cipher, cipher_len);
	*bloblen = cipher_len;

	/* Note: Do not even bother to return cipher directly. Would be freed during Context_Close anyways */
	Tspi_Context_FreeMemory(c, cipher);


close_ret:
	Tspi_Context_FreeMemory(c, NULL);
	Tspi_Context_Close(c);
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
	uint32_t pcrmask =  0x000000BF; // PCRs 0-5 and 7

	char *outfile_name;
	FILE *infile;
	FILE *outfile;
	QRcode *qrcode;
	int nxtarg;

	if (generate_key()) {
		return -1;
	}

	pcrvals = malloc(NUM_PCRS * sizeof(uint8_t*));
	CHECK_MALLOC(pcrvals);

	static int base32_flag = 0;
	static int qr_flag = 1;
	int option_index = 0;

	static struct option long_options[] = {
	     {"pcrs",  required_argument, 0, 'p'},
	     {"no-qrcode", no_argument, &qr_flag, 0},
	     {"base32", no_argument, &base32_flag, 1},
	     {"help", no_argument, 0, 'h'},
	     {0,0,0,0}

	};

	if (argc == 1) {
	     print_help();
	     exit(EXIT_FAILURE);
	}

	int c;

	while ((c = getopt_long(argc, argv, "p:nbh", long_options, &option_index)) != -1) {

		switch (c) {
		case 0: // Flag only
			break;

		case 'p':
			pcrmask = parse_pcrs(optarg);
			break;

		case 'h':
			print_help();
			return 0;

		case 'b':
			base32_flag = 1;
			break;

		case 'n':
			qr_flag = 0;
			break;

		case '?': // Unrecognized Option
			print_help();
			exit(EXIT_FAILURE);

		default:
			print_help();
		}

	}

	if (optind == argc) {
		fprintf(stderr, "Output name required!\n");
		print_help();
		exit(EXIT_FAILURE);
	} else {
		outfile_name = argv[optind];
	}

	base32_encode(key, keylen, base32_key);
	base32_key[BASE32_LEN(keylen)] = NULL;
//	ret = TPM_SealCurrPCR(0x40000000, // SRK
	ret = TSPI_SealCurrPCR(0x40000000, // SRK
			      pcrmask,
			      wellknown,  // Well-known SRK secret
			      wellknown,  // Well-known SEAL secret
			      key, keylen,	/* data to be sealed */
			      blob, &bloblen);	/* buffer to receive result */
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_Seal\n",
			TPM_GetErrMsg(ret));
		return -1;
	}

	sprintf(totpstring, "otpauth://totp/TPMTOTP?secret=%s", base32_key);

	if (qr_flag) {
		qrcode = QRcode_encodeString(totpstring, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
		writeANSI(qrcode);
	}

	if (base32_flag) {
		int j;
		for(j = 0; j < keylen; j++) {
			printf("%02x", 0xff & key[j]);
		}
		printf("\n");
	}

	outfile = fopen(outfile_name, "w");
	if (outfile == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n",
			outfile_name);
		return -1;
	}
	if (strncmp(outfile_name, efivarfs, strlen(efivarfs)) == 0) {
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
			outfile_name);
		return -1;
	}
	fclose(outfile);
	exit(0);
}
