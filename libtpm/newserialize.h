/********************************************************************************/
/*										*/
/*			     	TPM New Serialization Routines			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: newserialize.h 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#ifndef TPM_SERIALIZE_H
#define TPM_SERIALIZE_H


#define FORMAT_ENTRY(idx, string) \
  [idx] = string

enum {
    FORIDX_TPM_STRUCT_VER = 0,
    FORIDX_TPM_VERSION,
    FORIDX_TPM_KEY_HANDLE_LIST,
    FORIDX_TPM_CHANGEAUTH_VALIDATE,
    FORIDX_TPM_STORE_PUBKEY,
    FORIDX_TPM_PUBKEY,
    FORIDX_TPM_PCR_COMPOSITE,
    FORIDX_TPM_PCR_INFO_LONG,
    FORIDX_TPM_PCR_INFO_SHORT,
    FORIDX_TPM_STCLEAR_FLAGS,
    FORIDX_TPM_CONTEXT_BLOB,
};

#define FORMAT_TPM_STRUCT_VER "oooo"
#define PARAMS_TPM_STRUCT_VER(pre,x) \
   pre(x)->major, \
   pre(x)->minor, \
   pre(x)->revMajor, \
   pre(x)->revMinor


#define FORMAT_TPM_VERSION "oooo"
#define PARAMS_TPM_VERSION(pre,x) \
   pre(x)->major, \
   pre(x)->minor, \
   pre(x)->revMajor, \
   pre(x)->revMinor
   
#define FORMAT_TPM_KEY_HANDLE_LIST "a"
#define PARAMS_TPM_KEY_HANDLE_LIST(pre,x) \
   pre(x)->loaded,      \
   4, pre(x)->handle[0]


#define FORMAT_TPM_CHANGEAUTH_VALIDATE "%%"
#define PARAMS_TPM_CHANGEAUTH_VALIDATE(pre,x) \
   20, pre(x)->newAuthSecret, \
   20, pre(x)->n1


#define FORMAT_TPM_SIGN_INFO "S%%*"
#define PARAMS_TPM_SIGN_INFO(pre,x) \
   pre(x)->tag,        \
   4, pre(x)->fixed,   \
   20, pre(x)->replay, \
   pre(x)->data.size, pre(x)->data.buffer
#define PARAMS_TPM_SIGN_INFO_W(x) \
   PARAMS_TPM_SIGN_INFO(,x)
#define PARAMS_TPM_SIGN_INFO_R(x) \
   PARAMS_TPM_SIGN_INFO(&,x)   


#define FORMAT_TPM_PCR_SELECTION "^"
#define PARAMS_TPM_PCR_SELECTION(pre,x) \
   pre(x)->sizeOfSelect, sizeof((x)->pcrSelect), pre(x)->pcrSelect
#define PARAMS_TPM_PCR_SELECTION_W(x) \
   PARAMS_TPM_PCR_SELECTION(,x)
#define PARAMS_TPM_PCR_SELECTION_R(x) \
   PARAMS_TPM_PCR_SELECTION(&,x)


#define FORMAT_TPM_PCR_COMPOSITE FORMAT_TPM_PCR_SELECTION "*"
#define PARAMS_TPM_PCR_COMPOSITE(pre,x) \
   PARAMS_TPM_PCR_SELECTION(pre, &(x)->select), \
   pre(x)->pcrValue.size, pre(x)->pcrValue.buffer
#define PARAMS_TPM_PCR_COMPOSITE_W(x) \
   PARAMS_TPM_PCR_COMPOSITE(,x)
#define PARAMS_TPM_PCR_COMPOSITE_R(x) \
   PARAMS_TPM_PCR_COMPOSITE(&,x)

#define FORMAT_TPM_PCR_INFO_LONG "Soo" FORMAT_TPM_PCR_SELECTION FORMAT_TPM_PCR_SELECTION "%%"
#define PARAMS_TPM_PCR_INFO_LONG(pre,x) \
   pre(x)->tag,                \
   pre(x)->localityAtCreation, \
   pre(x)->localityAtRelease,  \
   PARAMS_TPM_PCR_SELECTION(pre, &(x)->creationPCRSelection),\
   PARAMS_TPM_PCR_SELECTION(pre, &(x)->releasePCRSelection), \
   TPM_DIGEST_SIZE, pre(x)->digestAtCreation, \
   TPM_DIGEST_SIZE, pre(x)->digestAtRelease
#define PARAMS_TPM_PCR_INFO_LONG_W(x) \
   PARAMS_TPM_PCR_INFO_LONG(,x)
#define PARAMS_TPM_PCR_INFO_LONG_R(x) \
   PARAMS_TPM_PCR_INFO_LONG(&,x)


#define FORMAT_TPM_KEY_PARMS "LSS@"
#define PARAMS_TPM_KEY_PARMS(pre,x) \
   pre(x)->algorithmID, \
   pre(x)->encScheme,   \
   pre(x)->sigScheme,   \
   pre(x)->parms.size, pre(x)->parms.buffer
#define PARAMS_TPM_KEY_PARMS_W(x) \
  PARAMS_TPM_KEY_PARMS(,x)
#define PARAMS_TPM_KEY_PARMS_R(x) \
  PARAMS_TPM_KEY_PARMS(&,x)


#define FORMAT_TPM_STORE_PUBKEY "@"
#define PARAMS_TPM_STORE_PUBKEY(pre,x) \
   pre(x)->keyLength, pre(x)->key
#define PARAMS_TPM_STORE_PUBKEY_W(x)\
   PARAMS_TPM_STORE_PUBKEY(,x)
#define PARAMS_TPM_STORE_PUBKEY_R(x)\
   PARAMS_TPM_STORE_PUBKEY(&,x)

#define FORMAT_TPM_PUBKEY FORMAT_TPM_KEY_PARAMS FORMAT_TPM_STORE_PUBKEY
#define PARAMS_TPM_PUBKEY(pre,x) \
   PARAMS_TPM_KEY_PARMS(pre, &(x)->algorithmParams), \
   PARAMS_TPM_STORE_PUBKEY(pre, &(x)->pubKey)
#define PARAMS_TPM_PUBKEY_W(x)\
   PARAMS_TPM_PUBKEY(,x)
#define PARAMS_TPM_PUBKEY_R(x)\
   PARAMS_TPM_PUBKEY(&,x)

#define FORMAT_TPM_MIGRATIONKEYAUTH FORMAT_TPM_PUBKEY "S%"
#define PARAMS_TPM_MIGRATIONKEYAUTH(pre,x) \
   PARAMS_TPM_PUBKEY_W(x), \
   pre(x)->migrationScheme,   \
   20, pre(x)->digest
#define PARAMS_TPM_MIGRATIONKEYAUTH_W(x)\
   PARAMS_TPM_MIGRATIONKEYAUTH(,x)
#define PARAMS_TPM_MIGRATIONKEYAUTH_R(x)\
   PARAMS_TPM_MIGRATIONKEYAUTH(&,x)

#define FORMAT_TPM_STCLEAR_FLAGS "Sooooo"
#define PARAMS_TPM_STCLEAR_FLAGS(pre,x) \
   pre(x)->tag, \
   pre(x)->deactivated, \
   pre(x)->disableForceClear, \
   pre(x)->physicalPresence,  \
   pre(x)->physicalPresenceLock, \
   pre(x)->bGlobalLock
#define PARAMS_TPM_STCLEAR_FLAGS_W(x) \
   PARAMS_TPM_STCLEAR_FLAGS(,x)
#define PARAMS_TPM_STCLEAR_FLAGS_R(x) \
   PARAMS_TPM_STCLEAR_FLAGS(&,x)


#define FORMAT_TPM_CONTEXT_BLOB "SLL%L%**"
#define PARAMS_TPM_CONTEXT_BLOB(pre,x) \
  pre(x)->tag, \
  pre(x)->resourceType, \
  pre(x)->handle, \
  TPM_CONTEXT_LABEL_SIZE, pre(x)->label, \
  pre(x)->contextCount, \
  TPM_HASH_SIZE, pre(x)->integrityDigest, \
  pre(x)->additionalData.size, pre(x)->additionalData.buffer, \
  pre(x)->sensitiveData.size, pre(x)->sensitiveData.buffer
#define PARAMS_TPM_CONTEXT_BLOB_W(x) \
   PARAMS_TPM_CONTEXT_BLOB(,x)
#define PARAMS_TPM_CONTEXT_BLOB_R(x) \
   PARAMS_TPM_CONTEXT_BLOB(&,x)

/* rev 62 */
#define FORMAT_TPM_PERMANENT_FLAGS17 "Sooooooooooooooo"
#define PARAMS_TPM_PERMANENT_FLAGS17(pre,x) \
   pre(x)->tag, 			\
   pre(x)->disable, 			\
   pre(x)->ownership, 			\
   pre(x)->deactivated,			\
   pre(x)->readPubek, 			\
   pre(x)->disableOwnerClear, 		\
   pre(x)->allowMaintenance, 		\
   pre(x)->physicalPresenceLifetimeLock, \
   pre(x)->physicalPresenceHWEnable, 	\
   pre(x)->physicalPresenceCMDEnable, 	\
   pre(x)->CEKPUsed, 			\
   pre(x)->TPMpost, 			\
   pre(x)->TPMpostLock, 		\
   pre(x)->FIPS, 			\
   pre(x)->tpmOperator, 			\
   pre(x)->enableRevokeEK
#define PARAMS_TPM_PERMANENT_FLAGS17_W(x) \
   PARAMS_TPM_PERMANENT_FLAGS17(,x)
#define PARAMS_TPM_PERMANENT_FLAGS17_R(x) \
   PARAMS_TPM_PERMANENT_FLAGS17(&,x)

/* rev 85 Atmel */
#define FORMAT_TPM_PERMANENT_FLAGS20 "Soooooooooooooooooo"
#define PARAMS_TPM_PERMANENT_FLAGS20(pre,x)	\
    pre(x)->tag,			\
    pre(x)->disable,			\
    pre(x)->ownership,			\
    pre(x)->deactivated,		\
    pre(x)->readPubek,			\
    pre(x)->disableOwnerClear,		\
    pre(x)->allowMaintenance,		\
    pre(x)->physicalPresenceLifetimeLock, \
    pre(x)->physicalPresenceHWEnable,	\
    pre(x)->physicalPresenceCMDEnable,	\
    pre(x)->CEKPUsed,			\
    pre(x)->TPMpost,			\
    pre(x)->TPMpostLock,		\
    pre(x)->FIPS,			\
    pre(x)->tpmOperator,		\
    pre(x)->enableRevokeEK,		\
    pre(x)->nvLocked,			\
    pre(x)->readSRKPub,			\
    pre(x)->tpmEstablished
#define PARAMS_TPM_PERMANENT_FLAGS20_W(x)	\
    PARAMS_TPM_PERMANENT_FLAGS20(,x)
#define PARAMS_TPM_PERMANENT_FLAGS20_R(x)	\
    PARAMS_TPM_PERMANENT_FLAGS20(&,x)

#define FORMAT_TPM_PERMANENT_FLAGS21 "Sooooooooooooooooooo"
#define PARAMS_TPM_PERMANENT_FLAGS21(pre,x)	\
    pre(x)->tag,				\
    pre(x)->disable,			\
    pre(x)->ownership,			\
    pre(x)->deactivated,		\
    pre(x)->readPubek,			\
    pre(x)->disableOwnerClear,		\
    pre(x)->allowMaintenance,		\
    pre(x)->physicalPresenceLifetimeLock, \
    pre(x)->physicalPresenceHWEnable,	\
    pre(x)->physicalPresenceCMDEnable,	\
    pre(x)->CEKPUsed,			\
    pre(x)->TPMpost,			\
    pre(x)->TPMpostLock,		\
    pre(x)->FIPS,			\
    pre(x)->tpmOperator,		\
    pre(x)->enableRevokeEK,		\
    pre(x)->nvLocked,			\
    pre(x)->readSRKPub,			\
    pre(x)->tpmEstablished,		\
    pre(x)->maintenanceDone
#define PARAMS_TPM_PERMANENT_FLAGS21_W(x)	\
    PARAMS_TPM_PERMANENT_FLAGS21(,x)
#define PARAMS_TPM_PERMANENT_FLAGS21_R(x)	\
    PARAMS_TPM_PERMANENT_FLAGS21(&,x)

#define FORMAT_TPM_PERMANENT_FLAGS22 "Soooooooooooooooooooo"
#define PARAMS_TPM_PERMANENT_FLAGS22(pre,x)	\
    pre(x)->tag,				\
    pre(x)->disable,			\
    pre(x)->ownership,			\
    pre(x)->deactivated,		\
    pre(x)->readPubek,			\
    pre(x)->disableOwnerClear,		\
    pre(x)->allowMaintenance,		\
    pre(x)->physicalPresenceLifetimeLock,	\
    pre(x)->physicalPresenceHWEnable,	\
    pre(x)->physicalPresenceCMDEnable,	\
    pre(x)->CEKPUsed,			\
    pre(x)->TPMpost,			\
    pre(x)->TPMpostLock,		\
    pre(x)->FIPS,			\
    pre(x)->tpmOperator,		\
    pre(x)->enableRevokeEK,		\
    pre(x)->nvLocked,			\
    pre(x)->readSRKPub,			\
    pre(x)->tpmEstablished,		\
    pre(x)->maintenanceDone,		\
    pre(x)->disableFullDALogicInfo
#define PARAMS_TPM_PERMANENT_FLAGS22_W(x)	\
    PARAMS_TPM_PERMANENT_FLAGS22(,x)
#define PARAMS_TPM_PERMANENT_FLAGS22_R(x)	\
    PARAMS_TPM_PERMANENT_FLAGS22(&,x)


#define FORMAT_TPM_PCR_INFO_SHORT FORMAT_TPM_PCR_SELECTION "o%"
#define PARAMS_TPM_PCR_INFO_SHORT(pre,x) \
   PARAMS_TPM_PCR_SELECTION(pre, &(x)->pcrSelection),\
   pre(x)->localityAtRelease, \
   TPM_HASH_SIZE, pre(x)->digestAtRelease
#define PARAMS_TPM_PCR_INFO_SHORT_W(x) \
  PARAMS_TPM_PCR_INFO_SHORT(,x)
#define PARAMS_TPM_PCR_INFO_SHORT_R(x) \
  PARAMS_TPM_PCR_INFO_SHORT(&,x)




#define FORMAT_TPM_PCR_INFO FORMAT_TPM_PCR_SELECTION "%%"
#define PARAMS_TPM_PCR_INFO(pre,x) \
   PARAMS_TPM_PCR_SELECTION(pre, &(x)->pcrSelection), \
   TPM_DIGEST_SIZE, pre(x)->digestAtRelease, \
   TPM_DIGEST_SIZE, pre(x)->digestAtCreation
#define PARAMS_TPM_PCR_INFO_W(x) \
   PARAMS_TPM_PCR_INFO(,x)
#define PARAMS_TPM_PCR_INFO_R(x) \
   PARAMS_TPM_PCR_INFO(&,x)


#define FORMAT_TPM_STORE_ASYMKEY "o%%%@@@"
#define PARAMS_TPM_STORE_ASYMKEY(pre,x) \
   pre(x)->payload, \
   TPM_SECRET_SIZE, pre(x)->usageAuth,\
   TPM_SECRET_SIZE, pre(x)->migrationAuth, \
   TPM_DIGEST_SIZE, pre(x)->pubDataDigest, \
   pre(x)->privKey.d_key.size, pre(x)->privKey.d_key.buffer, \
   pre(x)->privKey.p_key.size, pre(x)->privKey.p_key.buffer, \
   pre(x)->privKey.q_key.size, pre(x)->privKey.q_key.buffer
#define PARAMS_TPM_STORE_ASYMKEY_W(x) \
   PARAMS_TPM_STORE_ASYMKEY(,x)
#define PARAMS_TPM_STORE_ASYMKEY_R(x) \
   PARAMS_TPM_STORE_ASYMKEY(&,x)

#define FORMAT_TPM_STORED_DATA FORMAT_TPM_STRUCT_VER "**"
#define PARAMS_TPM_STORED_DATA(pre,x) \
   PARAMS_TPM_STRUCT_VER(pre,&(x)->ver), \
   pre(x)->sealInfo.size, pre(x)->sealInfo.buffer, \
   pre(x)->encData.size, pre(x)->encData.buffer
#define PARAMS_TPM_STORED_DATA_W(x) \
   PARAMS_TPM_STORED_DATA(,x)
#define PARAMS_TPM_STORED_DATA_R(x) \
   PARAMS_TPM_STORED_DATA(&,x)


#define FORMAT_TPM_CMK_AUTH "%%%"
#define PARAMS_TPM_CMK_AUTH(pre,x) \
   TPM_DIGEST_SIZE, pre(x)->migrationAuthorityDigest,\
   TPM_DIGEST_SIZE, pre(x)->destinationKeyDigest, \
   TPM_DIGEST_SIZE, pre(x)->sourceKeyDigest
#define PARAMS_TPM_CMK_AUTH_W(x) \
   PARAMS_TPM_CMK_AUTH(,x)
#define PARAMS_TPM_CMK_AUTH_R(x) \
   PARAMS_TPM_CMK_AUTH(&,x)

#define FORMAT_TPM_EK_BLOB_ACTIVATE "S" FORMAT_TPM_SYMMETRIC_KEY "%" FORMAT_TPM_PCR_INFO_SHORT
#define PARAMS_TPM_EK_BLOB_ACTIVATE(pre,x) \
  pre(x)->tag,\
  PARAMS_TPM_SYMMETRIC_KEY(pre,&(x)->sessionKey),\
  TPM_HASH_SIZE, pre(x)->idDigest,\
  PARAMS_TPM_PCR_INFO_SHORT(pre,&(x)->pcrInfo)
#define PARAMS_TPM_EK_BLOB_ACTIVATE_W(x) \
  PARAMS_TPM_EK_BLOB_ACTIVATE(,x)
#define PARAMS_TPM_EK_BLOB_ACTIVATE_R(x) \
  PARAMS_TPM_EK_BLOB_ACTIVATE(&,x)


#define FORMAT_TPM_EK_BLOB "SS*"
#define PARAMS_TPM_EK_BLOB(pre,x) \
  pre(x)->tag,\
  pre(x)->ekType,\
  pre(x)->blob.size, pre(x)->blob.buffer
#define PARAMS_TPM_EK_BLOB_W(x)\
  PARAMS_TPM_EK_BLOB(,x)
#define PARAMS_TPM_EK_BLOB_R(x)\
  PARAMS_TPM_EK_BLOB(&,x)


#define FORMAT_TPM_ASYM_CA_CONTENTS FORMAT_TPM_SYMMETRIC_KEY "%"
#define PARAMS_TPM_ASYM_CA_CONTENTS(pre,x) \
  PARAMS_TPM_SYMMETRIC_KEY(pre, &(x)->sessionKey),\
  TPM_HASH_SIZE, pre(x)->idDigest
#define PARAMS_TPM_ASYM_CA_CONTENTS_W(x) \
  PARAMS_TPM_ASYM_CA_CONTENTS(,x)
#define PARAMS_TPM_ASYM_CA_CONTENTS_R(x) \
  PARAMS_TPM_ASYM_CA_CONTENTS(&,x)


#define FORMAT_TPM_DELEGATIONS "SLLL"
#define PARAMS_TPM_DELEGATIONS(pre,x) \
  pre(x)->tag,\
  pre(x)->delegateType,\
  pre(x)->per1,\
  pre(x)->per2
#define PARAMS_TPM_DELEGATIONS_W(x)\
  PARAMS_TPM_DELEGATIONS(,x)
#define PARAMS_TPM_DELEGATIONS_R(x)\
  PARAMS_TPM_DELEGATIONS(&,x)


#define FORMAT_TPM_DELEGATE_PUBLIC "So" FORMAT_TPM_PCR_INFO_SHORT FORMAT_TPM_DELEGATIONS "LL"
#define PARAMS_TPM_DELEGATE_PUBLIC(pre,x) \
  pre(x)->tag,\
  pre(x)->rowLabel,\
  PARAMS_TPM_PCR_INFO_SHORT(pre,&(x)->pcrInfo),\
  PARAMS_TPM_DELEGATIONS(pre,&(x)->permissions),\
  pre(x)->familyID,\
  pre(x)->verificationCount
#define PARAMS_TPM_DELEGATE_PUBLIC_W(x)\
  PARAMS_TPM_DELEGATE_PUBLIC(,x)
#define PARAMS_TPM_DELEGATE_PUBLIC_R(x)\
  PARAMS_TPM_DELEGATE_PUBLIC(&,x)


#define FORMAT_TPM_DELEGATE_OWNER_BLOB "S" FORMAT_TPM_DELEGATE_PUBLIC "%**"
#define PARAMS_TPM_DELEGATE_OWNER_BLOB(pre,x) \
  pre(x)->tag,\
  PARAMS_TPM_DELEGATE_PUBLIC(pre,&(x)->pub),\
  TPM_DIGEST_SIZE, pre(x)->integrityDigest,\
  pre(x)->additionalArea.size, pre(x)->additionalArea.buffer,\
  pre(x)->sensitiveArea.size, pre(x)->sensitiveArea.buffer
#define PARAMS_TPM_DELEGATE_OWNER_BLOB_W(x)\
  PARAMS_TPM_DELEGATE_OWNER_BLOB(,x)
#define PARAMS_TPM_DELEGATE_OWNER_BLOB_R(x)\
  PARAMS_TPM_DELEGATE_OWNER_BLOB(&,x)

#define FORMAT_SIZED_BUFFER "*"
#define PARAMS_SIZED_BUFFER(pre,x) \
  pre(x)->size, pre(x)->buffer
#define PARAMS_SIZED_BUFFER_W(x)\
  PARAMS_SIZED_BUFFER(,x)
#define PARAMS_SIZED_BUFFER_R(x)\
  PARAMS_SIZED_BUFFER(&,x)

#define FORMAT_TPM_DELEGATE_KEY_BLOB "%%" FORMAT_SIZED_BUFFER FORMAT_SIZED_BUFFER
#define PARAMS_TPM_DELEGATE_KEY_BLOB(pre,x) \
  TPM_DIGEST_SIZE, pre(x)->integrityDigest,\
  TPM_DIGEST_SIZE, pre(x)->pubKeyDigest,\
  PARAMS_SIZED_BUFFER(pre,&(x)->additionalArea),\
  PARAMS_SIZED_BUFFER(pre,&(x)->sensitiveArea)
#define PARAMS_TPM_DELEGATE_KEY_BLOB_W(x)\
  PARAMS_TPM_DELEGATE_KEY_BLOB(,x)
#define PARAMS_TPM_DELEGATE_KEY_BLOB_R(x)\
  PARAMS_TPM_DELEGATE_KEY_BLOB(&,x)
  

#define FORMAT_TPM_TRANSPORT_PUBLIC "SLLS"
#define PARAMS_TPM_TRANSPORT_PUBLIC(pre,x) \
  pre(x)->tag,\
  pre(x)->transAttributes,\
  pre(x)->algId,\
  pre(x)->encScheme
#define PARAMS_TPM_TRANSPORT_PUBLIC_W(x)\
  PARAMS_TPM_TRANSPORT_PUBLIC(,x)
#define PARAMS_TPM_TRANSPORT_PUBLIC_R(x)\
  PARAMS_TPM_TRANSPORT_PUBLIC(&,x)


#define FORMAT_TPM_TRANSPORT_AUTH "S%"
#define PARAMS_TPM_TRANSPORT_AUTH(pre,x) \
  pre(x)->tag,\
  TPM_AUTHDATA_SIZE, pre(x)->authData
#define PARAMS_TPM_TRANSPORT_AUTH_W(x)\
  PARAMS_TPM_TRANSPORT_AUTH(,x)
#define PARAMS_TPM_TRANSPORT_AUTH_R(x)\
  PARAMS_TPM_TRANSPORT_AUTH(&,x)
  

#define FORMAT_TPM_QUOTE_INFO FORMAT_TPM_STRUCT_VER "%%%"
#define PARAMS_TPM_QUOTE_INFO(pre,x) \
  PARAMS_TPM_STRUCT_VER(pre, &(x)->version),\
  4, pre(x)->fixed,\
  TPM_HASH_SIZE, pre(x)->digestValue,\
  TPM_NONCE_SIZE, pre(x)->externalData
#define PARAMS_TPM_QUOTE_INFO_W(x)\
  PARAMS_TPM_QUOTE_INFO(,x)
#define PARAMS_TPM_QUOTE_INFO_R(x)\
  PARAMS_TPM_QUOTE_INFO(&,x)


#define FORMAT_TPM_QUOTE_INFO2 "S%%S%o%"
#define PARAMS_TPM_QUOTE_INFO2(pre,x) \
  pre(x)->tag,\
  4, pre(x)->fixed,\
  TPM_NONCE_SIZE, pre(x)->externalData,\
  PARAMS_TPM_PCR_INFO_SHORT(pre,&(x)->infoShort)
#define PARAMS_TPM_QUOTE_INFO2_W(x)\
  PARAMS_TPM_QUOTE_INFO2(,x)
#define PARAMS_TPM_QUOTE_INFO2_R(x)\
  PARAMS_TPM_QUOTE_INFO2(&,x)


#define FORMAT_TPM_CAP_VERSION_INFO "S" FORMAT_TPM_VERSION "So%S"
#define PARAMS_TPM_CAP_VERSION_INFO(pre,x) \
  pre(x)->tag,\
  PARAMS_TPM_VERSION(pre,&(x)->version),\
  pre(x)->specLevel,\
  pre(x)->errataRev,\
  4, pre(x)->tpmVendorID,\
  pre(x)->vendorSpecificSize
#define PARAMS_TPM_CAP_VERSION_INFO_W(x)\
  PARAMS_TPM_CAP_VERSION_INFO(,x)
#define PARAMS_TPM_CAP_VERSION_INFO_R(x)\
  PARAMS_TPM_CAP_VERSION_INFO(&,x)


#define FORMAT_TPM_NV_DATA_PUBLIC "SL" FORMAT_TPM_PCR_INFO_SHORT FORMAT_TPM_PCR_INFO_SHORT "SLoooL"
#define PARAMS_TPM_NV_DATA_PUBLIC(pre,x) \
   pre(x)->tag, \
   pre(x)->nvIndex, \
   PARAMS_TPM_PCR_INFO_SHORT(pre,&(x)->pcrInfoRead), \
   PARAMS_TPM_PCR_INFO_SHORT(pre,&(x)->pcrInfoWrite), \
   pre(x)->permission.tag, \
   pre(x)->permission.attributes, \
   pre(x)->bReadSTClear, \
   pre(x)->bWriteSTClear, \
   pre(x)->bWriteDefine, \
   pre(x)->dataSize
#define PARAMS_TPM_NV_DATA_PUBLIC_W(x) \
  PARAMS_TPM_NV_DATA_PUBLIC(,x)
#define PARAMS_TPM_NV_DATA_PUBLIC_R(x) \
  PARAMS_TPM_NV_DATA_PUBLIC(&,x)


#define FORMAT_TPM_SYMMETRIC_KEY "LS&"
#define PARAMS_TPM_SYMMETRIC_KEY(pre,x) \
   pre(x)->algId,\
   pre(x)->encScheme,\
   pre(x)->size, pre(x)->data
#define PARAMS_TPM_SYMMETRIC_KEY_W(x)\
  PARAMS_TPM_SYMMETRIC_KEY(,x)
#define PARAMS_TPM_SYMMETRIC_KEY_R(x)\
  PARAMS_TPM_SYMMETRIC_KEY(&,x)


#define FORMAT_TPM_FAMILY_TABLE_ENTRY "SoLLL"
#define PARAMS_TPM_FAMILY_TABLE_ENTRY(pre,x)\
  pre(x)->tag,\
  pre(x)->familyLabel,\
  pre(x)->familyID,\
  pre(x)->verificationCount,\
  pre(x)->flags
#define PARAMS_TPM_FAMILY_TABLE_ENTRY_W(x)\
  PARAMS_TPM_FAMILY_TABLE_ENTRY(,x)
#define PARAMS_TPM_FAMILY_TABLE_ENTRY_R(x)\
  PARAMS_TPM_FAMILY_TABLE_ENTRY(&,x)


#define FORMAT_TPM_CURRENT_TICKS "SLLS%"
#define PARAMS_TPM_CURRENT_TICKS(pre,x)\
  pre(x)->tag,\
  pre(x)->currentTicks.sec,\
  pre(x)->currentTicks.usec,\
  pre(x)->tickRate,\
  TPM_HASH_SIZE, pre(x)->tickNonce
#define PARAMS_TPM_CURRENT_TICKS_W(x)\
  PARAMS_TPM_CURRENT_TICKS(,x)
#define PARAMS_TPM_CURRENT_TICKS_R(x)\
  PARAMS_TPM_CURRENT_TICKS(&,x)


#define FORMAT_TPM_CERTIFY_INFO FORMAT_TPM_STRUCT_VER "SLo" FORMAT_TPM_KEY_PARMS "%%o" FORMAT_SIZED_BUFFER
#define PARAMS_TPM_CERTIFY_INFO(pre,x) \
  PARAMS_TPM_STRUCT_VER(pre, &(x)->version),\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TPM_KEY_PARMS(pre, &(x)->algorithmParms),\
  TPM_DIGEST_SIZE, pre(x)->pubkeyDigest,\
  TPM_NONCE_SIZE, pre(x)->data,\
  pre(x)->parentPCRStatus,\
  PARAMS_SIZED_BUFFER(pre, &(x)->pcrInfo)
#define PARAMS_TPM_CERTIFY_INFO_W(x)\
  PARAMS_TPM_CERTIFY_INFO(,x)
#define PARAMS_TPM_CERTIFY_INFO_R(x)\
  PARAMS_TPM_CERTIFY_INFO(&,x)


#define FORMAT_TPM_CERTIFY_INFO2 "SSLo" FORMAT_TPM_KEY_PARMS "%%o" FORMAT_SIZED_BUFFER FORMAT_SIZED_BUFFER
#define PARAMS_TPM_CERTIFY_INFO2(pre,x) \
  pre(x)->tag,\
  0,\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TPM_KEY_PARMS(pre, &(x)->algorithmParms),\
  TPM_DIGEST_SIZE, pre(x)->pubkeyDigest,\
  TPM_NONCE_SIZE, pre(x)->data,\
  pre(x)->parentPCRStatus,\
  PARAMS_SIZED_BUFFER(pre, &(x)->pcrInfo),\
  PARAMS_SIZED_BUFFER(pre, &(x)->migrationAuthority)
#define PARAMS_TPM_CERTIFY_INFO2_W(x)\
  PARAMS_TPM_CERTIFY_INFO2(,x)
#define PARAMS_TPM_CERTIFY_INFO2_R(x)\
  PARAMS_TPM_CERTIFY_INFO2(&,x)


#define FORMAT_TPM_COUNTER_VALUE "S%L"
#define PARAMS_TPM_COUNTER_VALUE(pre,x) \
  pre(x)->tag,\
  sizeof((x)->label), pre(x)->label,\
  pre(x)->counter
#define PARAMS_TPM_COUNTER_VALUE_W(x)\
  PARAMS_TPM_COUNTER_VALUE(,x)
#define PARAMS_TPM_COUNTER_VALUE_R(x)\
  PARAMS_TPM_COUNTER_VALUE(&,x)





#define FORMAT_TPM_PCR_LIST_TIMESTAMP "LL%LL"
#define PARAMS_TPM_PCR_LIST_TIMESTAMP(pre,x) \
  pre(x)->ordinal,\
  pre(x)->pcrIndex,\
  TPM_HASH_SIZE, pre(x)->digest,\
  pre(x)->timestamp_hi, \
  pre(x)->timestamp_lo
#define PARAMS_TPM_PCR_LIST_TIMESTAMP_W(x)\
  PARAMS_TPM_PCR_LIST_TIMESTAMP(,x)
#define PARAMS_TPM_PCR_LIST_TIMESTAMP_R(x)\
  PARAMS_TPM_PCR_LIST_TIMESTAMP(&,x)

#define FORMAT_TPM_PCR_LIST_TIMESTAMP_INST "LLL%LL"
#define PARAMS_TPM_PCR_LIST_TIMESTAMP_INST(pre,x) \
  pre(x)->instance,\
  pre(x)->ordinal,\
  pre(x)->pcrIndex,\
  TPM_HASH_SIZE, pre(x)->digest,\
  pre(x)->timestamp_hi, \
  pre(x)->timestamp_lo
#define PARAMS_TPM_PCR_LIST_TIMESTAMP_INST_W(x)\
  PARAMS_TPM_PCR_LIST_TIMESTAMP_INST(,x)
#define PARAMS_TPM_PCR_LIST_TIMESTAMP_INST_R(x)\
  PARAMS_TPM_PCR_LIST_TIMESTAMP_INST(&,x)


/*
 * TPM-client specific defines
 */
#define FORMAT_TPM_RSA_KEY_PARMS_EMB "LL#"
#define PARAMS_TPM_RSA_KEY_PARMS_EMB(pre,x,expsize) \
  pre(x)->keyLength,\
  pre(x)->numPrimes,\
  pre(x)->exponentSize/*expsize*/, sizeof((x)->exponent), pre(x)->exponent
#define PARAMS_TPM_RSA_KEY_PARMS_EMB_W(x,expsize)\
  PARAMS_TPM_RSA_KEY_PARMS_EMB(,x,expsize)
#define PARAMS_TPM_RSA_KEY_PARMS_EMB_R(x,expsize)\
  PARAMS_TPM_RSA_KEY_PARMS_EMB(&,x,expsize)

#define FORMAT_TPM_SYMMETRIC_KEY_PARMS_EMB "LL!"
#define PARAMS_TPM_SYMMETRIC_KEY_PARMS_EMB(pre,x) \
  pre(x)->keyLength,\
  pre(x)->blockSize,\
  pre(x)->ivSize, sizeof((x)->IV), pre(x)->IV
#define PARAMS_TPM_SYMMETRIC_KEY_PARMS_EMB_W(x)\
  PARAMS_TPM_SYMMETRIC_KEY_PARMS_EMB(,x)
#define PARAMS_TPM_SYMMETRIC_KEY_PARMS_EMB_R(x)\
  PARAMS_TPM_SYMMETRIC_KEY_PARMS_EMB(&,x)
  
#define FORMAT_TPM_KEY_PARMS_EMB_RSA "LSS" "X" FORMAT_TPM_RSA_KEY_PARMS_EMB
#define PARAMS_TPM_KEY_PARMS_EMB_RSA(pre,x)\
  pre(x)->algorithmID,\
  pre(x)->encScheme,\
  pre(x)->sigScheme,\
  12+(x)->u.rsaKeyParms.exponentSize, &(x)->u.rsaKeyParms.exponentSize,  /* length of serialized key parms */\
  PARAMS_TPM_RSA_KEY_PARMS_EMB(pre,&(x)->u.rsaKeyParms,0)
#define PARAMS_TPM_KEY_PARMS_EMB_RSA_W(x)\
  PARAMS_TPM_KEY_PARMS_EMB_RSA(,x)
#define PARAMS_TPM_KEY_PARMS_EMB_RSA_R(x)\
  PARAMS_TPM_KEY_PARMS_EMB_RSA(&,x)

#define FORMAT_TPM_KEY_PARMS_EMB_SYM ""
#define PARAMS_TPM_KEY_PARMS_EMB_SYM(pre,x)\
  pre(x)->algorithmID,\
  pre(x)->encScheme,\
  pre(x)->sigScheme,\
  PARAMS_TPM_SYMMETRIC_KEY_PARMS_EMB(pre,&(x)->u.symKeyParms)
#define PARAMS_TPM_KEY_PARMS_EMB_SYM_W(x)\
  PARAMS_TPM_KEY_PARMS_EMB_SYM(,x)
#define PARAMS_TPM_KEY_PARMS_EMB_SYM_R(x)\
  PARAMS_TPM_KEY_PARMS_EMB_SYM(&,x)


#define FORMAT_TPM_STORE_PUBKEY_EMB "!"
#define PARAMS_TPM_STORE_PUBKEY_EMB(pre,x)\
  pre(x)->keyLength,sizeof((x)->modulus),pre(x)->modulus
#define PARAMS_TPM_STORE_PUBKEY_EMB_W(x)\
  PARAMS_TPM_STORE_PUBKEY_EMB(,x)
#define PARAMS_TPM_STORE_PUBKEY_EMB_R(x)\
  PARAMS_TPM_STORE_PUBKEY_EMB(&,x)


#define FORMAT_TPM_AUDIT_EVENT_IN "S%" FORMAT_TPM_COUNTER_VALUE
#define PARAMS_TPM_AUDIT_EVENT_IN(pre,x)\
  pre(x)->tag,\
  20, pre(x)->inputParms,\
  PARAMS_TPM_COUNTER_VALUE(pre, &(x)->auditCount)
#define PARAMS_TPM_AUDIT_EVENT_IN_W(x)\
  PARAMS_TPM_AUDIT_EVENT_IN(,x)
#define PARAMS_TPM_AUDIT_EVENT_IN_R(x)\
  PARAMS_TPM_AUDIT_EVENT_IN(&,x)


#define FORMAT_TPM_AUDIT_EVENT_OUT "S%" FORMAT_TPM_COUNTER_VALUE
#define PARAMS_TPM_AUDIT_EVENT_OUT(pre,x)\
  pre(x)->tag,\
  20, pre(x)->outputParms,\
  PARAMS_TPM_COUNTER_VALUE(pre, &(x)->auditCount)
#define PARAMS_TPM_AUDIT_EVENT_OUT_W(x)\
  PARAMS_TPM_AUDIT_EVENT_OUT(,x)
#define PARAMS_TPM_AUDIT_EVENT_OUT_R(x)\
  PARAMS_TPM_AUDIT_EVENT_OUT(&,x)


#define FORMAT_TPM_DA_ACTION_TYPE "SL"
#define PARAMS_TPM_DA_ACTION_TYPE(pre,x)\
  pre(x)->tag,\
  pre(x)->actions
#define PARAMS_TPM_DA_ACTION_TYPE_W(x)\
  PARAMS_TPM_DA_ACTION_TYPE(,x)
#define PARAMS_TPM_DA_ACTION_TYPE_R(x)\
  PARAMS_TPM_DA_ACTION_TYPE(&,x)

#define FORMAT_TPM_DA_INFO "SoSS" FORMAT_TPM_DA_ACTION_TYPE "L*"
#define PARAMS_TPM_DA_INFO(pre,x)\
  pre(x)->tag,\
  pre(x)->state,\
  pre(x)->currentCount,\
  pre(x)->thresholdCount,\
  PARAMS_TPM_DA_ACTION_TYPE(pre, &(x)->actionAtThreshold),\
  pre(x)->actionDependValue,\
  pre(x)->vendorData.size, pre(x)->vendorData.buffer
#define PARAMS_TPM_DA_INFO_W(x)\
  PARAMS_TPM_DA_INFO(,x)
#define PARAMS_TPM_DA_INFO_R(x)\
  PARAMS_TPM_DA_INFO(&,x)

#define FORMAT_TPM_DA_INFO_LIMITED "So" FORMAT_TPM_DA_ACTION_TYPE "*"
#define PARAMS_TPM_DA_INFO_LIMITED(pre,x)\
  pre(x)->tag,\
  pre(x)->state,\
  PARAMS_TPM_DA_ACTION_TYPE(pre, &(x)->actionAtThreshold),\
  pre(x)->vendorData.size, pre(x)->vendorData.buffer
#define PARAMS_TPM_DA_INFO_LIMITED_W(x)\
  PARAMS_TPM_DA_INFO_LIMITED(,x)
#define PARAMS_TPM_DA_INFO_LIMITED_R(x)\
  PARAMS_TPM_DA_INFO_LIMITED(&,x)


#define FORMAT_TPM_KEY_EMB_RSA FORMAT_TPM_STRUCT_VER "SLo" FORMAT_TPM_KEY_PARMS_EMB_RSA "!" FORMAT_TPM_STORE_PUBKEY_EMB "!"
#define PARAMS_TPM_KEY_EMB_RSA(pre,x)\
  PARAMS_TPM_STRUCT_VER(pre, &(x)->v.ver),\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TPM_KEY_PARMS_EMB_RSA(pre, &(x)->pub.algorithmParms),\
  pre(x)->pub.pcrInfo.size, sizeof((x)->pub.pcrInfo.buffer), pre(x)->pub.pcrInfo.buffer,\
  PARAMS_TPM_STORE_PUBKEY_EMB(pre, &(x)->pub.pubKey),\
  pre(x)->encData.size, sizeof((x)->encData.buffer), pre(x)->encData.buffer
#define PARAMS_TPM_KEY_EMB_RSA_W(x)\
  PARAMS_TPM_KEY_EMB_RSA(,x)
#define PARAMS_TPM_KEY_EMB_RSA_R(x)\
  PARAMS_TPM_KEY_EMB_RSA(&,x)

#define FORMAT_TPM_PUBKEY_EMB_RSA FORMAT_TPM_KEY_PARMS_EMB_RSA FORMAT_TPM_STORE_PUBKEY_EMB
#define PARAMS_TPM_PUBKEY_EMB_RSA(pre,x)\
  PARAMS_TPM_KEY_PARMS_EMB_RSA(pre, &(x)->algorithmParms),\
  PARAMS_TPM_STORE_PUBKEY_EMB(pre, &(x)->pubKey)
#define PARAMS_TPM_PUBKEY_EMB_RSA_W(x)\
  PARAMS_TPM_PUBKEY_EMB_RSA(,x)
#define PARAMS_TPM_PUBKEY_EMB_RSA_R(x)\
  PARAMS_TPM_PUBKEY_EMB_RSA(&,x)

#define FORMAT_TPM_PUBKEY_EMB_SYM FORMAT_TPM_KEY_PARMS_EMB_SYM
#define PARAMS_TPM_PUBKEY_EMB_SYM(pre,x)\
  PARAMS_TPM_KEY_PARMS_EMB_SYM(pre, &(x)->algorithmParms)
#define PARAMS_TPM_PUBKEY_EMB_SYM_W(x)\
  PARAMS_TPM_PUBKEY_EMB_SYM(,x)
#define PARAMS_TPM_PUBKEY_EMB_SYM_R(x)\
  PARAMS_TPM_PUBKEY_EMB_SYM(&,x)

#define FORMAT_TPM_KEY12_EMB_RSA "SSSLo" FORMAT_TPM_KEY_PARMS_EMB_RSA "!" FORMAT_TPM_STORE_PUBKEY_EMB "!"
#define PARAMS_TPM_KEY12_EMB_RSA(pre,x)\
  pre(x)->v.tag,\
  pre(filler),\
  pre(x)->keyUsage,\
  pre(x)->keyFlags,\
  pre(x)->authDataUsage,\
  PARAMS_TPM_KEY_PARMS_EMB_RSA(pre, &(x)->pub.algorithmParms),\
  pre(x)->pub.pcrInfo.size, sizeof((x)->pub.pcrInfo.buffer), pre(x)->pub.pcrInfo.buffer,\
  PARAMS_TPM_STORE_PUBKEY_EMB(pre, &(x)->pub.pubKey),\
  pre(x)->encData.size, sizeof((x)->encData.buffer), pre(x)->encData.buffer
#define PARAMS_TPM_KEY12_EMB_RSA_W(x)\
  PARAMS_TPM_KEY12_EMB_RSA(,x)
#define PARAMS_TPM_KEY12_EMB_RSA_R(x)\
  PARAMS_TPM_KEY12_EMB_RSA(&,x)

#define FORMAT_TPM_TRANSPORT_LOG_IN "S%%"
#define PARAMS_TPM_TRANSPORT_LOG_IN(pre,x)\
  pre(x)->tag,\
  TPM_DIGEST_SIZE, pre(x)->parameters,\
  TPM_DIGEST_SIZE, pre(x)->pubKeyHash
#define PARAMS_TPM_TRANSPORT_LOG_IN_W(x)\
    PARAMS_TPM_TRANSPORT_LOG_IN(,x)
#define PARAMS_TPM_TRANSPORT_LOG_IN_R(x)\
    PARAMS_TPM_TRANSPORT_LOG_IN(&,x)

#define FORMAT_TPM_TRANSPORT_LOG_OUT "S" FORMAT_TPM_CURRENT_TICKS "%L"
#define PARAMS_TPM_TRANSPORT_LOG_OUT(pre,x)\
  pre(x)->tag,\
  PARAMS_TPM_CURRENT_TICKS(pre,&(x)->currentTicks),\
  TPM_DIGEST_SIZE, pre(x)->parameters,\
  pre(x)->locality
#define PARAMS_TPM_TRANSPORT_LOG_OUT_W(x)\
    PARAMS_TPM_TRANSPORT_LOG_OUT(,x)
#define PARAMS_TPM_TRANSPORT_LOG_OUT_R(x)\
    PARAMS_TPM_TRANSPORT_LOG_OUT(&,x)


#endif
