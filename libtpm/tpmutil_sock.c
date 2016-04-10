/********************************************************************************/
/*										*/
/*			     	TPM Socket Communication Functions		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil_sock.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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


/* These are platform specific.  This version uses a TCP/IP socket interface.

   Environment variables are:
           
   TPM_SERVER_PORT - the client and server socket port number
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>     

#ifdef TPM_POSIX
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <sys/types.h>
#include <fcntl.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"
#include "tpm_constants.h"
#include "tpmutil.h"
#include "tpm_lowlevel.h"

/* local prototypes */
static uint32_t TPM_OpenClientSocket(int *sock_fd);
static uint32_t TPM_CloseClientSocket(int sock_fd);
static uint32_t TPM_TransmitSocket(int sock_fd, struct tpm_buffer *tb,
                                   const char *msg);
static uint32_t TPM_ReceiveSocket(int sock_fd, struct tpm_buffer *tb);
static uint32_t TPM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,  
                                 size_t nbytes);


/* local variables */
static struct tpm_transport socket_transport = {
    .open = TPM_OpenClientSocket,
    .close = TPM_CloseClientSocket,
    .send = TPM_TransmitSocket,
    .recv = TPM_ReceiveSocket,
};

void TPM_LowLevel_TransportSocket_Set(void)
{
    TPM_LowLevel_Transport_Set(&socket_transport);
}

/****************************************************************************/
/*                                                                          */
/* Open the socket to the TPM Host emulation                                */
/*                                                                          */
/****************************************************************************/

/* For Windows, sock_fd is uint */

static uint32_t TPM_OpenClientSocket(int *sock_fd)
{
    int			irc;
#ifdef TPM_WINDOWS 
    WSADATA 		wsaData;
#endif
    char 		*port_str;
    short 		port;
    struct sockaddr_in 	serv_addr;
    struct hostent 	*host = NULL;
    char 		*server_name = NULL;

    port_str = getenv("TPM_SERVER_PORT");
    if (port_str == NULL) {
	printf("TPM_OpenClientSocket: Error, TPM_SERVER_PORT environment variable not set\n");
	return ERR_IO;
    }
    irc = sscanf(port_str, "%hu", &port);
    if (irc != 1) {
	printf("TPM_OpenClientSocket: Error, TPM_SERVER_PORT environment variable invalid\n");
	return ERR_IO;
    }
    /* get the server host name from the environment variable */
    server_name = getenv("TPM_SERVER_NAME");
    if (server_name == NULL) {        /* environment variable not found */
	printf("TPM_OpenClientSocket: TPM_SERVER_NAME environment variable not set\n");
	return ERR_IO;
    }
#ifdef TPM_WINDOWS
    if ((irc = WSAStartup(0x202, &wsaData)) != 0) {		/* if not successful */
	printf("TPM_OpenClientSocket: Error, WSAStartup failed\n");
	WSACleanup();
	return ERR_IO;
    }
    if ((*sock_fd = socket(AF_INET,SOCK_STREAM, 0)) == INVALID_SOCKET) {
	printf("TPM_OpenClientSocket: client socket() error: %u\n", *sock_fd);
	return ERR_IO;
    }
#endif 
#ifdef TPM_POSIX
    if ((*sock_fd = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
	printf("TPM_OpenClientSocket: client socket error: %d %s\n",errno,strerror(errno));
	return ERR_IO;
    }
    else {
	/*  	printf("TPM_OpenClientSocket: client socket: success\n"); */
    }
#endif
    /* establish the connection to server */
    memset((char *)&serv_addr,0x0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    /* first assume server is dotted decimal number and call inet_addr */
    if ((int)(serv_addr.sin_addr.s_addr = inet_addr(server_name)) == -1) {
	/* if inet_addr fails, assume server is a name and call gethostbyname to look it up */
	if ((host = gethostbyname(server_name)) == NULL) {	/* if gethostbyname also fails */
	    printf("TPM_OpenClientSocket: server name error, name %s\n", server_name);
	    return ERR_IO;
	}
	serv_addr.sin_family = host->h_addrtype;
	memcpy(&serv_addr.sin_addr, host->h_addr, host->h_length);
    }
    else {
/*  	printf("TPM_OpenClientSocket: server address: %s\n",server_name); */
    }
#ifdef TPM_POSIX
    if (connect(*sock_fd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
	printf("TPM_OpenClientsocket: Error on connect to %s:%u\n",server_name,port);
	printf("TPM_OpenClientsocket: client connect: error %d %s\n",errno,strerror(errno));
	return ERR_IO;
    }
#endif
#ifdef TPM_WINDOWS
    if (connect(*sock_fd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) != 0) {
	printf("TPM_OpenClientsocket: Error on connect to %s:%u\n",server_name,port);
	printf("TPM_OpenClientsocket: client connect: error %d %s\n",errno,strerror(errno));
	return ERR_IO;
    }
#endif
    else {
/*  	printf("TPM_OpenClientSocket: client connect: success\n"); */
    }
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Close the socket to the TPM Host emulation                               */
/*                                                                          */
/****************************************************************************/

static uint32_t TPM_CloseClientSocket(int sock_fd)
{
#ifdef TPM_POSIX
    if (close(sock_fd) != 0)
        return ERR_BAD_FILE_CLOSE;
#endif
#ifdef TPM_WINDOWS
    closesocket(sock_fd);
    WSACleanup();
#endif
    return 0;
}

/* write buffer to socket sock_fd */

static uint32_t TPM_TransmitSocket(int sock_fd, struct tpm_buffer *tb,
                                   const char *msg)
{
    size_t nbytes = 0;
    ssize_t nwritten = 0;
    size_t nleft = 0;
    unsigned int offset = 0;
    char mymsg[1024];
    
    snprintf(mymsg, sizeof(mymsg), "TPM_TransmitSocket: To TPM [%s]",
             msg);

    nbytes = tb->used;

    showBuff(tb->buffer, mymsg);

    nleft = nbytes;
    while (nleft > 0) {
#ifdef TPM_POSIX
	nwritten = write(sock_fd, &tb->buffer[offset], nleft);
	if (nwritten < 0) {        /* error */
	    printf("TPM_TransmitSocket: write error %d\n", (int)nwritten);
	    return ERR_IO;
	}
#endif
#ifdef TPM_WINDOWS
	/* cast for winsock.  Unix uses void * */
	nwritten = send(sock_fd, (char *)(&tb->buffer[offset]), nleft,0);
	if (nwritten == SOCKET_ERROR) {        /* error */
	    printf("TPM_TransmitSocket: write error %d\n", (int)nwritten);
	    return ERR_IO;
	}
#endif
	nleft -= nwritten;
	offset += nwritten;
    }
    return 0;
}

/* read a TPM packet from socket sock_fd */

static uint32_t TPM_ReceiveSocket(int sock_fd, struct tpm_buffer *tb)
{
    uint32_t rc = 0;
    uint32_t paramSize = 0;
    uint32_t addsize = 0;
    unsigned char *buffer = tb->buffer;

    if (TPM_LowLevel_Use_VTPM()) {
        addsize = sizeof(uint32_t);
    }

    /* read the tag and paramSize */
    if (rc == 0) {
	rc = TPM_ReceiveBytes(sock_fd, buffer, addsize + TPM_U16_SIZE + TPM_U32_SIZE);
    }
    /* extract the paramSize */
    if (rc == 0) {
	paramSize = LOAD32(buffer, addsize + TPM_PARAMSIZE_OFFSET);
	if (paramSize > TPM_MAX_BUFF_SIZE) {
	    printf("TPM_ReceiveSocket: ERROR: paramSize %u greater than %u\n",
		   paramSize, TPM_MAX_BUFF_SIZE);
	    rc = ERR_BAD_RESP;
	}
    }
    /* read the rest of the packet */
    if (rc == 0) {
	rc = TPM_ReceiveBytes(sock_fd,
			      buffer + addsize + TPM_U16_SIZE + TPM_U32_SIZE,
			      paramSize - (TPM_U16_SIZE + TPM_U32_SIZE));
    }
    /* read the TPM return code from the packet */
    if (rc == 0) {
	showBuff(buffer, "TPM_ReceiveSocket: From TPM");
	rc = LOAD32(buffer, addsize + TPM_RETURN_OFFSET);
        tb->used = addsize + paramSize;
    }
    return rc;
}

/* read nbytes from socket sock_fd and put them in buffer */

static uint32_t TPM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,  
                                 size_t nbytes)
{
    int nread = 0;
    int nleft = 0;

    nleft = nbytes;
    while (nleft > 0) {
#ifdef TPM_POSIX
	nread = read(sock_fd, buffer, nleft);
	if (nread <= 0) {       /* error */
	    printf("TPM_ReceiveBytes: read error %d\n", nread);
	    return ERR_IO;
	}
#endif
#ifdef TPM_WINDOWS
	/* cast for winsock.  Unix uses void * */
	nread = recv(sock_fd, (char *)buffer, nleft, 0);
	if (nread == SOCKET_ERROR) {       /* error */
	    printf("TPM_ReceiveBytes: read error %d\n", nread);
	    return ERR_IO;
	}
#endif
	else if (nread == 0) {  /* EOF */
	    printf("TPM_ReceiveBytes: read EOF\n");
	    return ERR_IO;
	}
	nleft -= nread;
	buffer += nread;
    }
    return 0;
}
