        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************




        OBJECTIVE :
	- This sample derives SLIP-10 master keypairs in bulk. A master has no path : it is
	  f(seed, curve). One seed and one curve produce exactly one master, so bulk masters
	  need one seed each. Multiple paths on the same seed are children, not masters;
	  that is what SLIP10_Derive_demo.c does.
	- Each thread generates (or reuses) its own 32 byte seed and calls CKM_BIP32_MASTER_DERIVE.
	- Luna does not publish CKM_SLIP10_* mechanisms. SLIP-10 is selected by setting CKA_ECDSA_PARAMS
	  on the BIP32 key templates. Firmware 7.8.7 or newer is required.
	- Keys are session objects unless a seed label prefix is supplied. With a prefix the seeds
	  are stored as <prefix>-0, <prefix>-1, ... so a later run rebuilds the same masters.

*/




#include <stdio.h>
#include <cryptoki_v2.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#ifdef OS_UNIX
        #include <dlfcn.h>
        #include <pthread.h>
#else
        #include <windows.h>
#endif


#ifdef OS_UNIX
        void *libHandle = 0;
#else
        HINSTANCE libHandle = 0;
#endif


CK_FUNCTION_LIST *p11Func = NULL;
CK_SESSION_HANDLE hSession = 0;
CK_SLOT_ID slotId = 0;
CK_BYTE *slotPin = NULL;
CK_BYTE *seedPrefix = NULL; // when set, seeds persist as <prefix>-<index>

CK_BBOOL yes = CK_TRUE;
CK_BBOOL no = CK_FALSE;

CK_BYTE versionBytesPub[] = {0x04, 0x88, 0xB2, 0x1E};
CK_BYTE versionBytesPri[] = {0x04, 0x88, 0xAD, 0xE4};

CK_BYTE oidSecp256k1[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};
CK_BYTE oidP256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
CK_BYTE oidEd25519[] = {0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01};

CK_BYTE *ecParam = NULL;
CK_ULONG ecParamLen = 0;
const char *curveName = NULL;
int nMasters = 0;


#ifdef OS_UNIX
        pthread_mutex_t printLock = PTHREAD_MUTEX_INITIALIZER;
#else
        CRITICAL_SECTION printLock;
#endif



void printLockInit()
{
#ifndef OS_UNIX
	InitializeCriticalSection(&printLock);
#endif
}



void printLockDestroy()
{
#ifndef OS_UNIX
	DeleteCriticalSection(&printLock);
#endif
}



void lockedPrint(const char *message)
{
#ifdef OS_UNIX
	pthread_mutex_lock(&printLock);
	fputs(message, stdout);
	fflush(stdout);
	pthread_mutex_unlock(&printLock);
#else
	EnterCriticalSection(&printLock);
	fputs(message, stdout);
	fflush(stdout);
	LeaveCriticalSection(&printLock);
#endif
}



void loadLunaLibrary()
{
	CK_C_GetFunctionList C_GetFunctionList = NULL;

	char *libPath = getenv("P11_LIB");
	if(libPath==NULL)
	{
		printf("P11_LIB environment variable not set.\n");
		printf("\n > On Unix/Linux :-\n");
		printf("export P11_LIB=<PATH_TO_CRYPTOKI>");
		printf("\n\n > On Windows :-\n");
		printf("set P11_LIB=<PATH_TO_CRYPTOKI>");
		printf("\n\nExample :-");
		printf("\nexport P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so");
		printf("\nset P11_LIB=C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll\n\n");
		exit(1);
	}

#ifdef OS_UNIX
	libHandle = dlopen(libPath, RTLD_NOW);
#else
	libHandle = LoadLibrary(libPath);
#endif

	if(!libHandle)
	{
		printf("Failed to load Luna library from path : %s\n", libPath);
		exit(1);
	}

#ifdef OS_UNIX
	C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle, "C_GetFunctionList");
#else
	C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList");
#endif

	if(C_GetFunctionList==NULL)
	{
		printf("Failed to load C_GetFunctionList.\n");
		exit(1);
	}

	C_GetFunctionList(&p11Func);
	if(p11Func==NULL)
	{
		printf("Failed to load P11 functions.\n");
		exit(1);
	}
	printf("\n> P11 library loaded.\n");
	printf("--> %s\n", libPath);
}



void freeMem()
{
	if(libHandle)
	{
#ifdef OS_UNIX
		dlclose(libHandle);
#else
		FreeLibrary(libHandle);
#endif
	}
	free(slotPin);
}



void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		printf("%s failed with 0x%lx\n\n", message, rv);
		if(p11Func!=NULL) p11Func->C_Finalize(NULL_PTR);
		exit(1);
	}
}



void connectToLunaSlot()
{
	checkOperation(p11Func->C_Initialize(NULL), "C_Initialize");
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &hSession), "C_OpenSession");
	checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen((const char*)slotPin)), "C_Login");
	printf("\n> Connected to Luna.\n");
	printf("--> SLOT ID : %lu.\n", slotId);
	printf("--> SESSION ID : %lu.\n", hSession);
}



void disconnectFromLunaSlot()
{
	checkOperation(p11Func->C_Logout(hSession), "C_Logout");
	checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
	checkOperation(p11Func->C_Finalize(NULL), "C_Finalize");
	printf("\n> Disconnected from Luna slot.\n\n");
}



int selectCurve(const char *name)
{
	if(strcmp(name, "secp256k1")==0)
	{
		ecParam = oidSecp256k1;
		ecParamLen = sizeof(oidSecp256k1);
		curveName = "secp256k1";
		return 0;
	}
	if(strcmp(name, "p256")==0)
	{
		ecParam = oidP256;
		ecParamLen = sizeof(oidP256);
		curveName = "NIST P-256";
		return 0;
	}
	if(strcmp(name, "ed25519")==0)
	{
		ecParam = oidEd25519;
		ecParamLen = sizeof(oidEd25519);
		curveName = "Ed25519";
		return 0;
	}
	return -1;
}



void fingerprintText(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, char *out, size_t outLen)
{
	CK_BYTE fingerprint[16] = {0};
	CK_ATTRIBUTE attrib[] = {{CKA_BIP32_FINGERPRINT, fingerprint, sizeof(fingerprint)}};
	CK_ULONG ctr = 0;

	out[0] = '\0';
	if(p11Func->C_GetAttributeValue(session, hKey, attrib, 1)!=CKR_OK)
		return;
	for(ctr=0; ctr<attrib[0].ulValueLen && ((ctr*2)+3)<outLen; ctr++)
		sprintf(out+(ctr*2), "%02x", fingerprint[ctr]);
}



// Finds a token seed under label, or CK_INVALID_HANDLE if none exists.
CK_OBJECT_HANDLE findSeedKey(CK_SESSION_HANDLE session, CK_BYTE *label)
{
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
	CK_ULONG objCount = 0;
	CK_ATTRIBUTE attrib[] =
	{
		{CKA_CLASS,	&objClass,	sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN,	&yes,		sizeof(CK_BBOOL)},
		{CKA_LABEL,	label,		(CK_ULONG)strlen((const char*)label)}
	};

	if(p11Func->C_FindObjectsInit(session, attrib, sizeof(attrib)/sizeof(*attrib))!=CKR_OK)
		return CK_INVALID_HANDLE;
	p11Func->C_FindObjects(session, &found, 1, &objCount);
	p11Func->C_FindObjectsFinal(session);
	return objCount ? found : CK_INVALID_HANDLE;
}



// One seed per master. With a prefix the seed is <prefix>-<index> on the token.
CK_RV obtainSeed(CK_SESSION_HANDLE session, int index, CK_OBJECT_HANDLE *seedOut, char *labelOut, size_t labelOutLen, int *reused)
{
	CK_MECHANISM mech = {CKM_GENERIC_SECRET_KEY_GEN};
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ULONG keyLen = 32;
	CK_ATTRIBUTE attrib[] =
	{
		{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
		{CKA_CLASS,		&objClass,		sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE,		&yes,			sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,		&yes,			sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,	&no,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,		&yes,			sizeof(CK_BBOOL)},
		{CKA_VALUE_LEN,		&keyLen,		sizeof(CK_ULONG)},
		{CKA_LABEL,		NULL,			0}
	};
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib) - 1;

	*reused = 0;
	labelOut[0] = '\0';

	if(seedPrefix!=NULL)
	{
		sprintf(labelOut, "%s-%d", seedPrefix, index);
		*seedOut = findSeedKey(session, (CK_BYTE*)labelOut);
		if(*seedOut!=CK_INVALID_HANDLE)
		{
			*reused = 1;
			return CKR_OK;
		}
		attrib[0].pValue = &yes;
		attrib[attribLen].pValue = labelOut;
		attrib[attribLen].ulValueLen = (CK_ULONG)strlen(labelOut);
		attribLen++;
	}

	return p11Func->C_GenerateKey(session, &mech, attrib, attribLen, seedOut);
}



#ifdef OS_UNIX
void *deriveMasterKeyPair(void *arg)
#else
DWORD WINAPI deriveMasterKeyPair(LPVOID arg)
#endif
{
	int index = (int)(intptr_t)arg;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE seedKey = CK_INVALID_HANDLE;
	CK_KEY_TYPE keyType = CKK_BIP32;
	CK_BYTE keyLabelPub[64];
	CK_BYTE keyLabelPri[64];
	CK_BIP32_MASTER_DERIVE_PARAMS masterParam;
	CK_MECHANISM mech;
	CK_RV rv = CKR_OK;
	char message[240];
	char fingerprint[40];
	char seedLabel[96];
	int reused = 0;

	sprintf((char*)keyLabelPub, "SLIP10-master-%d-public", index);
	sprintf((char*)keyLabelPri, "SLIP10-master-%d-private", index);

	CK_ATTRIBUTE attribPub[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,			&keyType,		sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,			keyLabelPub,		strlen((const char*)keyLabelPub)},
		{CKA_PRIVATE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_BIP32_VERSION_BYTES,	versionBytesPub,	sizeof(versionBytesPub)},
		{CKA_ECDSA_PARAMS,		ecParam,		ecParamLen}
	};
	CK_ATTRIBUTE attribPri[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,			&keyType,		sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,			keyLabelPri,		strlen((const char*)keyLabelPri)},
		{CKA_PRIVATE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_BIP32_VERSION_BYTES,	versionBytesPri,	sizeof(versionBytesPri)},
		{CKA_ECDSA_PARAMS,		ecParam,		ecParamLen}
	};

	memset(&masterParam, 0, sizeof(masterParam));
	masterParam.pPublicKeyTemplate = attribPub;
	masterParam.ulPublicKeyAttributeCount = sizeof(attribPub) / sizeof(*attribPub);
	masterParam.pPrivateKeyTemplate = attribPri;
	masterParam.ulPrivateKeyAttributeCount = sizeof(attribPri) / sizeof(*attribPri);
	masterParam.hPublicKey = CK_INVALID_HANDLE;
	masterParam.hPrivateKey = CK_INVALID_HANDLE;

	mech.mechanism = CKM_BIP32_MASTER_DERIVE;
	mech.pParameter = &masterParam;
	mech.ulParameterLen = sizeof(masterParam);

	rv = p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &session);
	if(rv!=CKR_OK)
	{
		sprintf(message, "--> Master %d : C_OpenSession failed with 0x%lx\n", index, rv);
		lockedPrint(message);
#ifdef OS_UNIX
		return (void*)(intptr_t)1;
#else
		return 1;
#endif
	}

	rv = obtainSeed(session, index, &seedKey, seedLabel, sizeof(seedLabel), &reused);
	if(rv!=CKR_OK)
	{
		sprintf(message, "--> Master %d : seed failed with 0x%lx\n", index, rv);
		lockedPrint(message);
		p11Func->C_CloseSession(session);
#ifdef OS_UNIX
		return (void*)(intptr_t)1;
#else
		return 1;
#endif
	}

	rv = p11Func->C_DeriveKey(session, &mech, seedKey, NULL, 0, NULL);
	if(rv==CKR_ATTRIBUTE_TYPE_INVALID || rv==CKR_MECHANISM_INVALID)
	{
		sprintf(message, "--> Master %d : slot %lu rejected the SLIP-10 templates. Firmware 7.8.7 or newer is required.\n",
			index, slotId);
		lockedPrint(message);
	}
	if(rv!=CKR_OK)
	{
		sprintf(message, "--> Master %d : C_DeriveKey failed with 0x%lx\n", index, rv);
		lockedPrint(message);
		p11Func->C_CloseSession(session);
#ifdef OS_UNIX
		return (void*)(intptr_t)1;
#else
		return 1;
#endif
	}

	fingerprintText(session, masterParam.hPublicKey, fingerprint, sizeof(fingerprint));
	if(seedPrefix!=NULL)
		sprintf(message, "--> Master %d : %s seed \"%s\". FINGERPRINT : %s, PUBLIC : %lu, PRIVATE : %lu\n",
			index, reused ? "reused" : "stored", seedLabel, fingerprint, masterParam.hPublicKey, masterParam.hPrivateKey);
	else
		sprintf(message, "--> Master %d : derived. FINGERPRINT : %s, PUBLIC : %lu, PRIVATE : %lu\n",
			index, fingerprint, masterParam.hPublicKey, masterParam.hPrivateKey);
	lockedPrint(message);
	p11Func->C_CloseSession(session);
#ifdef OS_UNIX
	return (void*)(intptr_t)0;
#else
	return 0;
#endif
}



void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_officer_password> <curve> <number_of_masters> [seed_label_prefix]\n\n", exeName);
	printf("curve : secp256k1 | p256 | ed25519\n");
	printf("--> A master is f(seed, curve). There is no path. Bulk masters need one seed each.\n");
	printf("--> Requires Luna firmware 7.8.7 or newer.\n");
	printf("--> seed_label_prefix is optional. Without it every run creates new session seeds.\n");
	printf("    With it the seeds persist as <prefix>-0, <prefix>-1, ... and a later run\n");
	printf("    with the same prefix rebuilds the same masters.\n\n");
	printf("Example :-\n");
	printf("%s 0 userpin secp256k1 4\n", exeName);
	printf("%s 0 userpin secp256k1 4 wallet\n\n", exeName);
}



int main(int argc, char *argv[])
{
	int failed = 0;
	int ctr = 0;

	printf("\n%s\n", argv[0]);
	if(argc<5 || argc>6)
	{
		usage(argv[0]);
		exit(1);
	}

	slotId = atoi(argv[1]);
	slotPin = (CK_BYTE*)malloc(strlen(argv[2]) + 1);
	strcpy((char*)slotPin, argv[2]);

	if(selectCurve(argv[3])!=0)
	{
		printf("\nUnsupported curve : %s\n", argv[3]);
		usage(argv[0]);
		free(slotPin);
		exit(1);
	}

	nMasters = atoi(argv[4]);
	if(nMasters<1)
	{
		printf("\nnumber_of_masters must be greater than zero.\n");
		usage(argv[0]);
		free(slotPin);
		exit(1);
	}

	if(argc==6) seedPrefix = (CK_BYTE*)argv[5];

	printLockInit();
	loadLunaLibrary();
	connectToLunaSlot();
	printf("\n> Deriving %d master keypair(s) on %s, one seed per thread.\n\n", nMasters, curveName);

#ifdef OS_UNIX
	{
		pthread_t *threads = (pthread_t*)malloc(nMasters * sizeof(pthread_t));
		for(ctr=0; ctr<nMasters; ctr++)
			pthread_create(&threads[ctr], NULL, deriveMasterKeyPair, (void*)(intptr_t)ctr);

		for(ctr=0; ctr<nMasters; ctr++)
		{
			void *threadReturn = 0;
			pthread_join(threads[ctr], &threadReturn);
			if((intptr_t)threadReturn!=0) failed++;
		}
		free(threads);
	}
#else
	{
		HANDLE *threads = (HANDLE*)malloc(nMasters * sizeof(HANDLE));
		for(ctr=0; ctr<nMasters; ctr++)
			threads[ctr] = CreateThread(NULL, 0, deriveMasterKeyPair, (LPVOID)(intptr_t)ctr, 0, NULL);

		for(ctr=0; ctr<nMasters; ctr++)
		{
			DWORD threadReturn = 0;
			WaitForSingleObject(threads[ctr], INFINITE);
			GetExitCodeThread(threads[ctr], &threadReturn);
			if(threadReturn!=0) failed++;
			CloseHandle(threads[ctr]);
		}
		free(threads);
	}
#endif

	printf("\n> %d of %d master keypair(s) derived.\n", nMasters-failed, nMasters);
	if(seedPrefix!=NULL)
		printf("\n> Seeds \"%s-0\" .. \"%s-%d\" stay on the token. Run again with the same prefix to rebuild them.\n",
			seedPrefix, seedPrefix, nMasters-1);
	disconnectFromLunaSlot();
	printLockDestroy();
	freeMem();
	return (failed==0) ? 0 : 1;
}
