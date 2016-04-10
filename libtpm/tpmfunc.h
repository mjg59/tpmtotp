/********************************************************************************/
/*										*/
/*			     	TPM Functions					*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmfunc.h 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#ifndef TPMFUNC_H
#define TPMFUNC_H

#include <stdint.h>
#include <tpmkeys.h>
#include <tpmutil.h>

#include <oiaposap.h>
#include <tpm_structures.h>

/* section 3: Admin startup and state */
uint32_t TPM_Init(void); /* just for testing */
uint32_t TPM_Startup(uint16_t type);
uint32_t TPM_SaveState(void);

/* section 4: Testing */
uint32_t TPM_SelfTestFull(void);
uint32_t TPM_ContinueSelfTest(void);
uint32_t TPM_GetTestResult(char * buffer, uint32_t * bufferlen);
uint32_t TPM_CertifySelfTest(uint32_t keyhandle,
                             unsigned char *usageAuth,  // HMAC key
                             unsigned char *antiReplay,
                             struct tpm_buffer *signature);

/* section 5: Admin Opt-in */
uint32_t TPM_SetOwnerInstall(TPM_BOOL state);
uint32_t TPM_OwnerSetDisable(unsigned char *ownerauth,  // HMAC key
                             TPM_BOOL state);
uint32_t TPM_PhysicalEnable(void);
uint32_t TPM_PhysicalDisable(void);
uint32_t TPM_PhysicalSetDeactivated(TPM_BOOL state);
uint32_t TPM_SetTempDeactivated(unsigned char *operatorauth  // HMAC key
                            );
uint32_t TPM_SetOperatorAuth(unsigned char * operatorAuth);

/* Basic TPM_ commands */
uint32_t TPM_CreateEndorsementKeyPair(unsigned char * pubkeybuff, 
                                      uint32_t * pubkeybuflen);
uint32_t TPM_CreateRevocableEK(TPM_BOOL genreset,
                               unsigned char * inputekreset,
                               pubkeydata * k);
uint32_t TPM_RevokeTrust(unsigned char *ekreset);
uint32_t TPM_ReadPubek(pubkeydata *k);
uint32_t TPM_DisablePubekRead(unsigned char *ownauth);
uint32_t TPM_OwnerReadPubek(unsigned char *ownauth,pubkeydata *k);
uint32_t TPM_OwnerReadInternalPub(uint32_t keyhandle,
                                  unsigned char * ownerauth,
                                  pubkeydata *k);


/* section 6: admin ownership */
uint32_t TPM_TakeOwnership(unsigned char *ownpass,
			   unsigned char *srkpass,
                           uint32_t keylen,
			   unsigned char *pcrInfoBuffer,
			   uint32_t pcrInfoSize,
			   keydata *key, TPM_BOOL v12);
uint32_t TPM_TakeOwnership12(unsigned char *ownpass, unsigned char *srkpass,
			     keydata *key);
uint32_t TPM_OwnerClear(unsigned char *ownpass);
uint32_t TPM_OwnerClear12(unsigned char *ownpass);
uint32_t TPM_ForceClear(void);
uint32_t TPM_DisableOwnerClear(unsigned char *ownerauth);
uint32_t TPM_DisableForceClear(void);
uint32_t TSC_PhysicalPresence(uint16_t ppresence);
uint32_t TPM_ResetEstablishmentBit(void);

/* section 8: auditing */
uint32_t TPM_GetAuditDigest(uint32_t startOrdinal,
                            TPM_COUNTER_VALUE * countervalue,
                            unsigned char * digest,
                            TPM_BOOL * more,
                            uint32_t ** ord, uint32_t * ordSize);

uint32_t TPM_GetAuditDigestSigned(uint32_t keyhandle,
                                  TPM_BOOL closeAudit,
                                  unsigned char *usageAuth,  // HMAC key
                                  unsigned char *antiReplay,
                                  TPM_COUNTER_VALUE * countervalue,
                                  unsigned char * auditDigest,
                                  unsigned char * ordinalDigest,
                                  struct tpm_buffer *signature
                                 );

uint32_t TPM_SetOrdinalAuditStatus(uint32_t ordinalToAudit,
                                   TPM_BOOL auditState,
                                   unsigned char *ownerAuth  // HMAC key
                                 );


uint32_t TPM_CreateWrapKey(uint32_t keyhandle,
                  unsigned char *keyauth, unsigned char *newauth,
                  unsigned char *migauth,
                  keydata *keyparms,keydata *key,
                  unsigned char *keyblob, unsigned int *bloblen);
uint32_t TPM_EvictKey(uint32_t keyhandle);
uint32_t TPM_EvictKey_UseRoom(uint32_t keyhandle);

/* section 9: Administrative functions: Management */
uint32_t TPM_SetRedirection(uint32_t keyhandle,
                            uint32_t redirCmd,
                            unsigned char * inputData, uint32_t inputDataSize,
                            unsigned char * ownerAuth,
                            unsigned char * usageAuth);
uint32_t TPM_ResetLockValue(unsigned char * ownerAuth);

/* section 12: Maintenance */
uint32_t TPM_CreateMaintenanceArchive(TPM_BOOL generateRandom,
                                      unsigned char * ownerAuth,
                                      unsigned char * random, uint32_t * randomSize,
                                      unsigned char * archive, uint32_t * archiveSize);
uint32_t TPM_LoadMaintenanceArchive(unsigned char * ownerAuth);
uint32_t TPM_KillMaintenanceFeature(unsigned char * ownerAuth);
uint32_t TPM_LoadManuMaintPub(unsigned char *nonce,
                              keydata * pubKey,
                              unsigned char * digest);
uint32_t TPM_ReadManuMaintPub(unsigned char *nonce,
                              unsigned char * digest);

/* section 15: Identity creation and activation */
uint32_t TPM_MakeIdentity(unsigned char * identityauth,
                          unsigned char * identitylabel,
                          keydata * keyparms,
                          keydata * key,
			  unsigned char *keyblob,
			  unsigned int  *keybloblen,
			  unsigned char * srkAuth,
                          unsigned char * ownerAuth,
                          unsigned char * idbinding, uint32_t * idbsize
                          );
uint32_t TPM_ActivateIdentity(uint32_t keyhandle,
                              unsigned char * blob, uint32_t blobsize,
                              unsigned char * usageAuth,
                              unsigned char * ownerAuth,
                              struct tpm_buffer *symkey
                          );



/* Section 16: Integrity collection and reporting */
uint32_t TPM_Extend(uint32_t pcrIndex,
                    unsigned char * event,
                    unsigned char * outDigest);
uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue);
uint32_t TPM_Quote(uint32_t keyhandle,
                   unsigned char *keyauth,
                   unsigned char *externalData,
                   TPM_PCR_SELECTION *tps,
                   TPM_PCR_COMPOSITE *tpc,
                   struct tpm_buffer *signature);
uint32_t TPM_PCRReset(TPM_PCR_SELECTION * selection);
uint32_t TPM_Quote2(uint32_t keyhandle,
                    TPM_PCR_SELECTION * selection,
                    TPM_BOOL addVersion,
                    unsigned char *keyauth,
                    unsigned char * antiReplay,
                    TPM_PCR_INFO_SHORT * pcrinfo,
                    struct tpm_buffer *versionblob,
                    struct tpm_buffer *signature);

/* Section 17: Authorization Changing */
uint32_t TPM_ChangeKeyAuth(uint32_t keyhandle,
                           unsigned char *parauth,
                           unsigned char *keyauth,
                           unsigned char *newauth,
                           keydata *key);
uint32_t TPM_ChangeAuth(uint32_t keyhandle,
                        unsigned char *parauth,
                        unsigned char *keyauth,
                        unsigned char *newauth,
                        unsigned short etype,
                        unsigned char *encdata, uint32_t encdatalen);
uint32_t TPM_ChangeSRKAuth(unsigned char *ownauth,
                           unsigned char *newauth);
uint32_t TPM_ChangeOwnAuth(unsigned char *ownauth,
                           unsigned char *newauth);

/* Section 18 */
uint32_t TPM_SetOwnerPointer(uint16_t entityType, 
                             uint32_t entityValue);


/* Section 19: Delegation */
uint32_t TPM_Delegate_Manage(uint32_t familyID,
                             uint32_t opFlag,
                             unsigned char * opData, uint32_t opDataLen,
                             unsigned char * ownerAuth,
                             unsigned char * retData, uint32_t * retDataLen);
uint32_t TPM_Delegate_CreateKeyDelegation(uint32_t keyhandle,
                                          TPM_DELEGATE_PUBLIC *tdp,
                                          unsigned char *blobAuth,
                                          unsigned char *usageAuth,
                                          unsigned char *blob, uint32_t *blobSize
                                          );
uint32_t TPM_Delegate_CreateOwnerDelegation(
                                            TPM_BOOL increment,
                                            TPM_DELEGATE_PUBLIC *tdp,
                                            unsigned char * blobAuth,
                                            unsigned char * ownerAuth,
                                            unsigned char * blob, uint32_t *blobSize
                                          );
uint32_t TPM_Delegate_LoadOwnerDelegation(uint32_t index,
                                          unsigned char * ownerAuth,
                                          unsigned char * blob, uint32_t blobSize
                                          );
uint32_t TPM_Delegate_UpdateVerification(unsigned char * inputData, uint32_t inputDataSize,
                                         unsigned char * ownerAuth,
                                         unsigned char * outputData, uint32_t * outputDataSize);
uint32_t TPM_Delegate_ReadTable(unsigned char * familyTable  , uint32_t * familyTableSize,
                                unsigned char * delegateTable, uint32_t * delegateTableSize);
uint32_t TPM_Delegate_VerifyDelegation(unsigned char * delegation, uint32_t delegationLen);


/* Section 21: Session Management */
uint32_t TPM_KeyControlOwner(unsigned char *ownerauth,  // HMAC key
                             uint32_t keyhandle,
                             keydata *pubKey,
                             uint32_t bitname,
                             TPM_BOOL bitvalue);
uint32_t TPM_SaveContext(uint32_t handle,
                         uint32_t resourceType,
                         char * label,
                         struct tpm_buffer *context);
uint32_t TPM_SaveContext_UseRoom(uint32_t handle,
                                 uint32_t resourceType,
                                 char * label,
                                 struct tpm_buffer *context);
uint32_t TPM_LoadContext(uint32_t entityHandle,
                         TPM_BOOL keephandle,
                         struct tpm_buffer *context,
                         uint32_t * handle);



/* Section 22: Eviction */
uint32_t TPM_FlushSpecific(uint32_t handle,
                           uint32_t resourceType);


/* Section 23: tpm timer tick functions */
uint32_t TPM_GetTicks(unsigned char * tickbuffer);
uint32_t TPM_TickStampBlob(uint32_t keyhandle,
                           unsigned char *digestToStamp,
                           unsigned char *usageauth,
                           unsigned char *antiReplay,
                           unsigned char *tickbuff,
                           struct tpm_buffer *signature);

/* Section 24: transport commands */
uint32_t TPM_EstablishTransport(uint32_t keyhandle,
                                unsigned char *usageAuth,
                                TPM_TRANSPORT_PUBLIC *ttp,
                                unsigned char *transAuth,
                                struct tpm_buffer *secret,
                                TPM_CURRENT_TICKS *currentticks,
                                session *transSession);
uint32_t TPM_EstablishTransport_UseRoom(uint32_t keyhandle,
                                        unsigned char *usageAuth,
                                        TPM_TRANSPORT_PUBLIC *ttp,
                                        unsigned char *transAuth,
                                        struct tpm_buffer *secret,
                                        TPM_CURRENT_TICKS *currentticks,
                                        session *transSession);
uint32_t TPM_ExecuteTransport(struct tpm_buffer *tb, const char *msg);
uint32_t TPM_ReleaseTransportSigned(uint32_t keyhandle,
                                    unsigned char * usageAuth,
                                    session *transSession,
                                    unsigned char *antiReplay,
                                    struct tpm_buffer *signature,
                                    unsigned char *transDigest);
void *TSS_SetTransportFunction(uint32_t (*function)(struct tpm_buffer *tb, 
                                                    const char *msg));
void *TSS_PushTransportFunction(uint32_t (*function)(struct tpm_buffer *tb,
                                                     const char *msg),
                                uint32_t *idx);
void *TSS_PopTransportFunction(uint32_t *idx);
void TSS_ClearTransports(void);

uint32_t TSS_SetTransportParameters(session *transSession,
                                    uint32_t idx);


/* Section 26: DAA commands */
uint32_t TPM_DAA_Join(uint32_t sesshandle,
                      unsigned char * ownerauth,    // HMAC key
                      unsigned char stage,
                      unsigned char * inputData0, uint32_t inputData0Size,
                      unsigned char * inputData1, uint32_t inputData1Size, 
                      unsigned char * outputData, uint32_t * outputDataSize
                      );
uint32_t TPM_DAA_Sign(uint32_t sesshandle,
                      unsigned char * ownerauth,    // HMAC key
                      unsigned char stage,
                      unsigned char * inputData0, uint32_t inputData0Size,
                      unsigned char * inputData1, uint32_t inputData1Size, 
                      unsigned char * outputData, uint32_t * outputDataSize
                      );


/* Section 10: Storage Functions */
uint32_t TPM_Seal(uint32_t keyhandle,
                  unsigned char *pcrinfo, uint32_t pcrinfosize,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, uint32_t datalen,
                  unsigned char *blob, uint32_t *bloblen);
uint32_t TPM_Unseal(uint32_t keyhandle,
                    unsigned char *keyauth,
                    unsigned char *dataauth,
                    unsigned char *blob, uint32_t bloblen,
                    unsigned char *rawdata, uint32_t *datalen);
uint32_t TPM_UnBind(uint32_t keyhandle,
                    unsigned char *keyauth,
                    unsigned char *data, uint32_t datalen,
                    unsigned char *blob, uint32_t *bloblen);
uint32_t TSS_Bind(RSA *key,
                  const struct tpm_buffer *data,
                  struct tpm_buffer *blob);
uint32_t TSS_BindPKCSv15(RSA *key,
                         const struct tpm_buffer *data,
                         struct tpm_buffer *blob);
uint32_t TPM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
                     keydata *keyparms,uint32_t *newhandle);
uint32_t TPM_LoadKey2(uint32_t keyhandle, unsigned char *keyauth,
                      keydata *keyparms, uint32_t *newhandle);
uint32_t TPM_GetPubKey(uint32_t keyhandle,
                       unsigned char *keyauth,
                       pubkeydata *pk);
uint32_t TPM_GetPubKey_UseRoom(uint32_t keyhandle,
                               unsigned char *keyauth,
                               pubkeydata *pk);
uint32_t TPM_Sealx(uint32_t keyhandle,
                   TPM_PCR_INFO_LONG *pil,
                   unsigned char *keyauth,
                   unsigned char *dataauth,
                   unsigned char *data, uint32_t datalen,
                   unsigned char *blob, uint32_t *bloblen);
uint32_t TPM_Unsealx(uint32_t keyhandle,
                     unsigned char *keyauth,
                     unsigned char *dataauth,
                     unsigned char *blob, uint32_t bloblen,
                     unsigned char *rawdata, uint32_t *datalen);

/* section 7: capability commands */
uint32_t TPM_GetCapability(uint32_t caparea, 
                           struct tpm_buffer *scap,
                           struct tpm_buffer *response);
uint32_t TPM_GetCapability_NoTransport(uint32_t caparea,
                                       struct tpm_buffer *scap,
                                       struct tpm_buffer *response);
uint32_t TPM_SetCapability(uint32_t caparea, 
                           unsigned char *subcap, uint32_t subcaplen, 
                           struct tpm_buffer *setValue,
                           unsigned char * operatorauth);
uint32_t TPM_GetCapabilitySigned(uint32_t keyhandle,
                                 unsigned char * keypass,
                                 unsigned char * antiReplay,
                                 uint32_t caparea, 
                                 struct tpm_buffer *scap,
                                 struct tpm_buffer *resp,
                                 unsigned char *sig , uint32_t *siglen);


uint32_t TPM_GetCapabilityOwner(unsigned char *ownpass,
                                uint32_t *volflags, uint32_t *nvolflags);


/* Section 11: Migration */
uint32_t TPM_AuthorizeMigrationKey(unsigned char *ownpass,
                                   int migtype,
                                   struct tpm_buffer *keyblob,
                                   struct tpm_buffer *migblob);
uint32_t TPM_CreateMigrationBlob(unsigned int keyhandle,
                                 unsigned char *keyauth,
                                 unsigned char *migauth,
                                 int migtype,
                                 unsigned char *migblob,
                                 uint32_t   migblen,
                                 unsigned char *keyblob,
                                 uint32_t   keyblen,
                                 unsigned char *rndblob,
                                 uint32_t  *rndblen,
                                 unsigned char *outblob,
                                 uint32_t  *outblen);
uint32_t TPM_ConvertMigrationBlob(unsigned int keyhandle,
                          unsigned char *keyauth,
                          unsigned char *rndblob,
                          uint32_t   rndblen,
                          unsigned char *keyblob,
                          uint32_t   keyblen,
                          unsigned char *encblob,
                          uint32_t  *encblen);

uint32_t TPM_MigrateKey(uint32_t keyhandle,
                        unsigned char * keyUsageAuth,
                        unsigned char * pubKeyBlob, uint32_t pubKeySize,
                        unsigned char * inData, uint32_t inDataSize,
                        unsigned char * outData, uint32_t * outDataSize);

uint32_t TPM_CMK_SetRestrictions(uint32_t restriction,
                                 unsigned char * ownerAuth);

uint32_t TPM_CMK_ApproveMA(unsigned char * migAuthDigest,
                           unsigned char * ownerAuth,
                           unsigned char * hmac);

uint32_t TPM_CMK_CreateKey(uint32_t parenthandle,
                           unsigned char * keyUsageAuth,
                           unsigned char * dataUsageAuth,
                           keydata * keyRequest,
                           unsigned char * migAuthApproval,
                           unsigned char * migAuthDigest,
                           keydata * key,
                           unsigned char * blob, uint32_t * bloblen);

uint32_t TPM_CMK_CreateTicket(keydata * key,
                              unsigned char * signedData,
                              unsigned char * signatureValue, uint32_t signatureValueSize,
                              unsigned char * ownerAuth,
                              unsigned char * ticketBuf);

uint32_t TPM_CMK_CreateBlob(uint32_t parenthandle,
                            unsigned char * parkeyUsageAuth,
                            uint16_t migScheme,
                            const struct tpm_buffer *migblob,
                            unsigned char * sourceKeyDigest,
                            TPM_MSA_COMPOSITE * msaList,
                            TPM_CMK_AUTH * resTicket,
                            unsigned char * sigTicket, uint32_t sigTicketSize,
                            unsigned char * encData, uint32_t encDataSize,
                            unsigned char * random, uint32_t * randomSize,
                            unsigned char * outData, uint32_t * outDataSize);

uint32_t TPM_CMK_ConvertMigration(uint32_t parenthandle,
                                  unsigned char * keyUsageAuth,
                                  TPM_CMK_AUTH * resTicket,
                                  unsigned char * sigTicket,
                                  keydata * key,
                                  TPM_MSA_COMPOSITE * msaList,
                                  unsigned char * random, uint32_t randomSize,
                                  unsigned char * outData, uint32_t * outDataSize);

uint32_t TPM_Reset(void);


/* Section 20: NV storage related functions */
uint32_t TPM_NV_DefineSpace(unsigned char *ownauth,  // HMAC key
                            unsigned char *pubInfo, uint32_t pubInfoSize,
                            unsigned char *keyauth   // used to create  encAuth
                            );
uint32_t TPM_NV_DefineSpace2(unsigned char *ownauth,  // HMAC key
                             uint32_t index,
                             uint32_t size,
                             uint32_t permissions,
                             unsigned char *areaauth,
			     TPM_PCR_INFO_SHORT *pcrInfoRead,
			     TPM_PCR_INFO_SHORT *pcrInfoWrite);
uint32_t TPM_NV_WriteValue(uint32_t nvIndex,
                           uint32_t offset,
                           unsigned char *data, uint32_t datalen,
                           unsigned char * ownauth) ;
uint32_t TPM_NV_WriteValueAuth(uint32_t nvIndex,
                               uint32_t offset,
                               unsigned char *data, uint32_t datalen,
                               unsigned char * areaauth) ;
uint32_t TPM_NV_ReadValue(uint32_t nvIndex,
                          uint32_t offset,
                          uint32_t datasize,
                          unsigned char * buffer, uint32_t * buffersize,
                          unsigned char * ownauth) ;
uint32_t TPM_NV_ReadValueAuth(uint32_t nvIndex,
                              uint32_t offset,
                              uint32_t datasize,
                              unsigned char * buffer, uint32_t * buffersize,
                              unsigned char * areaauth) ;


/* Section 25: Counter related functions */
uint32_t TPM_CreateCounter(uint32_t keyhandle,
                           unsigned char * ownauth,     // HMAC key
                           uint32_t label,              // label for counter
                           unsigned char * counterauth, //  authdata for counter
                           uint32_t * counterId,
                           unsigned char * counterValue
                           );
uint32_t TPM_IncrementCounter(uint32_t countid,              // id of the counter
                              unsigned char * counterauth,   // authdata for counter
                              unsigned char * counterbuffer  // buffer to return the counter in
                             );
uint32_t TPM_ReadCounter(uint32_t countid,              // id of the counter
                         unsigned char * counterauth,   // authdata for counter
                         unsigned char * counterbuffer // buffer to return the counter in
                         );
uint32_t TPM_ReleaseCounter(uint32_t countid,              // id of the counter
                            unsigned char * counterauth   // authdata for counter
                         );
uint32_t TPM_ReleaseCounterOwner(uint32_t countid,              // id of the counter
                                 unsigned char * ownerauth      // authdata for counter
                         );

/* Section 13: crypto functions */
uint32_t TPM_SHA1Start(uint32_t *maxNumBytes);
uint32_t TPM_SHA1Update(void * data, uint32_t datalen);
uint32_t TPM_SHA1Complete(void * data, uint32_t datalen,
                          unsigned char * hash);
uint32_t TPM_SHA1CompleteExtend(void * data, uint32_t datalen,
                                uint32_t pcrNum,
                                unsigned char * hash,
                                unsigned char * pcrValue) ;
uint32_t TPM_Sign(uint32_t keyhandle, unsigned char *keyauth,
                  unsigned char *data, uint32_t datalen,
                  unsigned char *sig, uint32_t *siglen);
uint32_t TPM_GetRandom(uint32_t bytesreq,
                       unsigned char * buffer, uint32_t * bytesret);
uint32_t TPM_StirRandom(unsigned char * data, uint32_t datalen);
uint32_t TPM_CertifyKey(uint32_t certhandle,
                        uint32_t keyhandle,
                        unsigned char *certKeyAuth,
                        unsigned char *usageAuth,
                        struct tpm_buffer *certifyInfo,
                        struct tpm_buffer *signature);
uint32_t TPM_CertifyKey2(uint32_t certhandle,
                         uint32_t keyhandle,
                         unsigned char * migrationPubDigest,
                         unsigned char * certKeyAuth,
                         unsigned char * usageAuth,
                         struct tpm_buffer *certifyInfo,
                         struct tpm_buffer *signature);

/* Section 28.2: Context management */
uint32_t TPM_SaveKeyContext(uint32_t keyhandle,
                            struct tpm_buffer *context);
uint32_t TPM_LoadKeyContext(struct tpm_buffer *buffer,
                            uint32_t *keyhandle);
uint32_t TPM_SaveAuthContext(uint32_t authhandle,
                             unsigned char * authContextBlob, uint32_t * authContextSize);
uint32_t TPM_LoadAuthContext(unsigned char *authContextBlob, uint32_t authContextSize,
                             uint32_t *keyhandle);

/* Section 28.3: Dir commands */
uint32_t TPM_DirWriteAuth(uint32_t dirIndex,
                          unsigned char * newValue,
                          unsigned char * ownerAuth);
uint32_t TPM_DirRead(uint32_t dirIndex,
                     unsigned char * dirValueBuffer) ;


/* virtual TPM Management functions */

/* TPM helper functions */
uint32_t TPM_SealCurrPCR(uint32_t keyhandle,
                  uint32_t pcrmap,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, uint32_t datalen,
                  unsigned char *blob, uint32_t *bloblen);
uint32_t TSS_GenPCRInfo(uint32_t pcrmap, 
                        unsigned char *pcrinfo, 
                        uint32_t *len);
char *TPM_GetErrMsg(uint32_t code);

uint32_t TPM_GetCurrentTicks(const struct tpm_buffer *tb, uint32_t offset, TPM_CURRENT_TICKS * ticks) ;




/* Additional functions for testing... */
uint32_t TPM_RawDataRaw(uint32_t ordinal,
                        unsigned char * data, 
                        uint32_t datalen);

uint32_t TPM_RawDataOIAP(uint32_t ordinal,
                         unsigned char * ownerauth,
                         unsigned char * data, 
                         uint32_t datalen);

uint32_t TPM_RawDataOSAP(uint32_t keyhandle,
                         uint32_t ordinal,
                         unsigned char * ownerauth,
                         unsigned char * data, 
                         uint32_t datalen);

void TPM_CreateEncAuth(const struct session *sess, 
                       const unsigned char *in, unsigned char *out,
                       const unsigned char *nonceodd);

uint32_t TPM_ValidatePCRCompositeSignature(TPM_PCR_COMPOSITE *tpc,
                                           unsigned char *antiReplay,
                                           pubkeydata *pk,
                                           struct tpm_buffer *signature,
                                           uint16_t sigscheme);


/* helper functions to serialize / deserialize data structures */

uint32_t TPM_WriteEkBlobActivate(struct tpm_buffer *buffer, TPM_EK_BLOB_ACTIVATE * blob) ;
uint32_t TPM_WriteEkBlob(struct tpm_buffer *buffer, TPM_EK_BLOB * blob);

uint32_t TPM_WritePCRComposite(struct tpm_buffer *tb, TPM_PCR_COMPOSITE *comp);
uint32_t TPM_ReadPCRComposite(const struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_COMPOSITE *tpc);


uint32_t TPM_ReadCounterValue(const unsigned char *buffer, TPM_COUNTER_VALUE * counter);
uint32_t TPM_WriteCounterValue(struct tpm_buffer *tb, TPM_COUNTER_VALUE * counter);
uint32_t TPM_WriteSignInfo(struct tpm_buffer *tb,
                           TPM_SIGN_INFO *tsi);
uint32_t TPM_WriteStoreAsymkey(struct tpm_buffer *buffer, TPM_STORE_ASYMKEY * sak);
uint32_t TPM_ReadStoredData(struct tpm_buffer *buffer, uint32_t offset, TPM_STORED_DATA *sd);
uint32_t TPM_WriteStoredData(struct tpm_buffer *buffer, TPM_STORED_DATA *sd);

uint32_t TPM_WritePCRInfoShort(struct tpm_buffer *buffer, TPM_PCR_INFO_SHORT * info);
uint32_t TPM_ReadPCRInfoLong(struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_INFO_LONG * info);
uint32_t TPM_WritePCRInfoLong(struct tpm_buffer *buffer, TPM_PCR_INFO_LONG * info);
uint32_t TPM_ReadPCRInfo(struct tpm_buffer *buffer, uint32_t offset, TPM_PCR_INFO *info);
uint32_t TPM_WritePCRInfo(struct tpm_buffer *buffer, TPM_PCR_INFO * info);
uint32_t TPM_ReadPCRInfoShort(const struct tpm_buffer *buffer, uint32_t offset, 
                              TPM_PCR_INFO_SHORT * info);

uint32_t TPM_WriteCAContents(struct tpm_buffer *buffer, TPM_ASYM_CA_CONTENTS * data);

uint32_t TPM_HashPCRComposite(TPM_PCR_COMPOSITE * comp, unsigned char * digest);
uint32_t TPM_HashPubKey(keydata * k, unsigned char * digest);
uint32_t TPM_HashMSAComposite(TPM_MSA_COMPOSITE * comp, unsigned char * digest);

uint32_t TPM_WriteMSAComposite(struct tpm_buffer *buffer, TPM_MSA_COMPOSITE * comp);
uint32_t TPM_ReadMSAFile(const char * filename, TPM_MSA_COMPOSITE * msaList);

uint32_t TPM_ReadKeyfile(const char * filename, keydata *k);
uint32_t TPM_ReadPubKeyfile(const char * filename, pubkeydata *pubk);
uint32_t TPM_WritePCRSelection(struct tpm_buffer *buffer,
                               TPM_PCR_SELECTION *sel);
uint32_t TPM_ReadPCRSelection(struct tpm_buffer *buffer, uint32_t offset,
                              TPM_PCR_SELECTION * sel);

uint32_t TPM_ReadFile(const char * filename, unsigned char ** buffer, uint32_t * buffersize);
uint32_t TPM_WriteFile(const char * filename, unsigned char * buffer, uint32_t buffersize);

uint32_t TPM_WriteQuoteInfo(struct tpm_buffer *buffer, TPM_QUOTE_INFO * info);
uint32_t TPM_WriteQuoteInfo2(struct tpm_buffer *buffer, TPM_QUOTE_INFO2 * info2);

uint32_t TPM_WriteCMKAuth(struct tpm_buffer *buffer, TPM_CMK_AUTH * auth) ;
uint32_t TPM_HashCMKAuth(TPM_CMK_AUTH * auth, unsigned char * hash);

uint32_t TPM_WritePubInfo(TPM_NV_DATA_PUBLIC * pub, struct tpm_buffer *buffer);

uint32_t TPM_ReadPermanentFlags(const struct tpm_buffer *tb,
                                uint32_t offset, 
                                TPM_PERMANENT_FLAGS * pf,
				uint32_t used);
uint32_t TPM_ReadPermanentFlagsPre103(const struct tpm_buffer *tb,
                                      uint32_t offset, 
                                      TPM_PERMANENT_FLAGS * pf);
uint32_t TPM_ReadSTClearFlags(const struct tpm_buffer *tb, 
                              uint32_t offset,
                              TPM_STCLEAR_FLAGS * sf);

uint32_t  TSS_KeyExtract(const struct tpm_buffer *tb, uint32_t offset, keydata *k);
uint32_t  TSS_PubKeyExtract(const struct tpm_buffer *tb, uint32_t offset, pubkeydata *k);
RSA      *TSS_convpubkey(pubkeydata *k);
uint32_t  TPM_WriteKey(struct tpm_buffer *tb, keydata *k);
uint32_t  TPM_ReadKey(const struct tpm_buffer *tb, uint32_t offset, keydata *k);
uint32_t  TPM_WriteKeyPub(struct tpm_buffer *tp, keydata *k);
uint32_t  TPM_WriteKeyInfo(struct tpm_buffer *tp, keydata *k);
uint32_t  TPM_WriteSymmetricKey(struct tpm_buffer *tp, TPM_SYMMETRIC_KEY * key);
uint32_t  TPM_ReadSymmetricKey(struct tpm_buffer *, uint32_t offset, TPM_SYMMETRIC_KEY * key);
int       TSS_KeySize(const struct tpm_buffer *tb, unsigned int offset);
int       TSS_PubKeySize(const struct tpm_buffer *, unsigned int offset, int pcrpresent);
int       TSS_AsymKeySize(const unsigned char * keybuff);
int       TSS_SymKeySize(const unsigned char * keybuff);
void      TSS_Key2Pub(unsigned char *keybuff, unsigned char *pkey, unsigned int *plen);
void      TSS_pkeyprint(pubkeydata *key, unsigned char *fprint);
void      TSS_keyprint(unsigned char *keybuff, unsigned char *fprint);
uint32_t  TSS_lkeyprint(uint32_t keyhandle, unsigned char *keyauth, unsigned char *fprint);
uint32_t  TPM_WriteStoreAsymkey(struct tpm_buffer *buffer, TPM_STORE_ASYMKEY * sak);

uint32_t TPM_GetCertifyInfoSize(const unsigned char * blob);
uint32_t TPM_GetCertifyInfo2Size(const unsigned char * blob);

uint32_t TPM_GetPubKeyDigest(uint32_t handle, unsigned char *keyPassHash, unsigned char *digest);

uint32_t TPM_WriteMigrationKeyAuth(struct tpm_buffer *buffer, TPM_MIGRATIONKEYAUTH * mka);
uint32_t TPM_WriteDelegatePublic(struct tpm_buffer *buffer, TPM_DELEGATE_PUBLIC * pub);
uint32_t TPM_ReadKeyParms(const struct tpm_buffer *, uint32_t offset, TPM_KEY_PARMS * keyparms);
uint32_t TPM_ReadCertifyInfo(const struct tpm_buffer *, uint32_t offset, TPM_CERTIFY_INFO * cinfo);
uint32_t TPM_ReadCertifyInfo2(const struct tpm_buffer *, uint32_t offset, TPM_CERTIFY_INFO2 * cinfo2);
uint32_t TPM_ReadNVDataPublic(const struct tpm_buffer *buffer, uint32_t offset, TPM_NV_DATA_PUBLIC * ndp);
uint32_t TPM_ReadCapVersionInfo(const struct tpm_buffer *fb, uint32_t offset, TPM_CAP_VERSION_INFO * cvi);
uint32_t TPM_ReadStartupEffects(const unsigned char * buffer, TPM_STARTUP_EFFECTS * se);

uint32_t TPM_GetNumPCRRegisters(uint32_t *res);
uint32_t TPM_GetTPMInputBufferSize(uint32_t *size);

struct tpm_buffer *TSS_AllocTPMBuffer(int len);
void TSS_FreeTPMBuffer(struct tpm_buffer * buf);
uint32_t TSS_SetTPMBuffer(struct tpm_buffer *tb, 
                          const unsigned char *buffer,
                          uint32_t len);

uint32_t TPM_WriteTPMFamilyLabel(struct tpm_buffer *buffer, 
                                 TPM_FAMILY_LABEL l);
uint32_t TPM_ReadTPMFamilyLabel(const unsigned char *buffer, 
                                TPM_FAMILY_LABEL *l);
uint32_t TPM_WriteTPMDelegations(struct tpm_buffer *buffer,
                                 TPM_DELEGATIONS *td);
uint32_t TPM_WriteTPMDelegatePublic(struct tpm_buffer *buffer,
                                    TPM_DELEGATE_PUBLIC * tdp);
uint32_t TPM_WriteTPMDelegateOwnerBlob(struct tpm_buffer *buffer,
                                       TPM_DELEGATE_OWNER_BLOB *tdob);
uint32_t TPM_WriteTPMDelegateKeyBlob(struct tpm_buffer *buffer,
                                     TPM_DELEGATE_KEY_BLOB *tdob);
uint32_t TPM_WriteDelegateOwnerBlob(struct tpm_buffer *buffer, TPM_DELEGATE_OWNER_BLOB * blob);

uint32_t TPM_ReadFamilyTableEntry(struct tpm_buffer *buffer,
                                  uint32_t offset,
                                  TPM_FAMILY_TABLE_ENTRY *fte);
uint32_t TPM_ReadDelegatePublic(struct tpm_buffer *buffer,
                                uint32_t offset,
                                TPM_DELEGATE_PUBLIC *dp);
uint32_t TPM_ReadTPMDelegations(const struct tpm_buffer *buffer, uint32_t offset,
                                TPM_DELEGATIONS *td);
uint32_t TPM_WriteTransportPublic(struct tpm_buffer *tb,
                                  TPM_TRANSPORT_PUBLIC *ttp);
uint32_t TPM_WriteTransportAuth(struct tpm_buffer *tb,
                                TPM_TRANSPORT_AUTH *tta);
uint32_t TPM_WriteContextBlob(struct tpm_buffer *buffer,
                              TPM_CONTEXT_BLOB * context);
uint32_t TPM_ReadContextBlob(const struct tpm_buffer *buffer,
                             uint32_t offset,
                             TPM_CONTEXT_BLOB *context);
uint32_t TPM_WriteAuditEventIn(struct tpm_buffer *buffer, 
                               TPM_AUDIT_EVENT_IN * aei);
uint32_t TPM_WriteAuditEventOut(struct tpm_buffer *buffer,
                                TPM_AUDIT_EVENT_OUT * aeo);
uint32_t TPM_ReadDAInfo(struct tpm_buffer *buffer,
                        uint32_t offset,
                        TPM_DA_INFO *tdi);
uint32_t TPM_ReadDAInfoLimited(struct tpm_buffer *buffer,
                               uint32_t offset,
                               TPM_DA_INFO_LIMITED *tdi);
uint32_t _TPM_GetCalculatedAuditDigest(TPM_DIGEST *digest);
uint32_t _TPM_SetAuditStatus(uint32_t ord, TPM_BOOL enable);

uint32_t TPM_ValidateSignature(uint16_t sigscheme,
                               struct tpm_buffer *data,
                               struct tpm_buffer *signature,
                               RSA *rsa);
uint32_t TPM_WriteTransportLogIn(struct tpm_buffer *buffer,
                                 TPM_TRANSPORT_LOG_IN *ttli);
uint32_t TPM_WriteTransportLogOut(struct tpm_buffer *buffer,
                                  TPM_TRANSPORT_LOG_OUT *ttlo);
uint32_t TPM_WriteCurrentTicks(struct tpm_buffer *buffer,
                               TPM_CURRENT_TICKS *tct);
uint32_t TPM_ReadCurrentTicks(struct tpm_buffer *buffer,
                              uint32_t offset,
                              TPM_CURRENT_TICKS *tct);

uint32_t read_transdigest(uint32_t handle, unsigned char *digest);



void print_array(const char *name, const unsigned char *data, unsigned int len);

#endif
