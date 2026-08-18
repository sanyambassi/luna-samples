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
	- This sample demonstrates SLIP-10 hierarchical deterministic key derivation on a Luna HSM.
	- A 32 byte generic secret is generated as the seed, CKM_BIP32_MASTER_DERIVE turns it into a master keypair,
	  and CKM_BIP32_CHILD_DERIVE walks a BIP-44 path to derive one distinct child leaf per thread.
	- Luna does not publish CKM_SLIP10_* mechanisms. SLIP-10 is selected by setting CKA_ECDSA_PARAMS on the
	  BIP32 key templates. Without that attribute the firmware performs classic BIP-32, which is secp256k1 only.
	- SLIP-10 adds NIST P-256 and Ed25519 to the curves BIP-32 supports, and requires firmware 7.8.7 or newer.
	- Ed25519 has no public parent to public child derivation, so every index of an Ed25519 path must be hardened.
	- Keys are session objects (CKA_TOKEN=CK_FALSE) unless a seed label is supplied, in which case only the seed
	  becomes a token object. A later run finds that seed and rebuilds the identical tree, which is how a real
	  deployment works : the seed is the one thing worth storing, everything below it is recomputed on demand.

*/




#include <stdio.h>
#include <cryptoki_v2.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


// Windows and Linux OS uses different header files for loading libraries.
#ifdef OS_UNIX
        #include <dlfcn.h> // For Unix/Linux OS.
        #include <pthread.h>
#else
        #include <windows.h> // For Windows OS.
#endif


// Windows uses HINSTANCE for storing library handles.
#ifdef OS_UNIX
        void *libHandle = 0; // Library handle for Unix/Linux
#else
        HINSTANCE libHandle = 0; //Library handle for Windows.
#endif


CK_FUNCTION_LIST *p11Func = NULL;
CK_SESSION_HANDLE hSession = 0;
CK_SLOT_ID slotId = 0; // slot id
CK_BYTE *slotPin = NULL; // slot password
CK_BYTE *seedLabel = NULL; // when set, the seed is kept as a token object under this label

CK_BBOOL yes = CK_TRUE;
CK_BBOOL no = CK_FALSE;

CK_OBJECT_HANDLE seedKey = 0;
CK_OBJECT_HANDLE masterKeyPub = 0;
CK_OBJECT_HANDLE masterKeyPri = 0;

// BIP-32 mainnet version bytes, the same values that prefix an xpub and an xprv.
CK_BYTE versionBytesPub[] = {0x04, 0x88, 0xB2, 0x1E};
CK_BYTE versionBytesPri[] = {0x04, 0x88, 0xAD, 0xE4};

// DER encoded OIDs of the three curves SLIP-10 defines.
CK_BYTE oidSecp256k1[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};
CK_BYTE oidP256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
CK_BYTE oidEd25519[] = {0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01};

CK_BYTE *ecParam = NULL;
CK_ULONG ecParamLen = 0;
int curveIsEd25519 = 0;
const char *curveName = NULL;
int nChildren = 0;


// Worker threads share stdout, so printing is serialized.
#ifdef OS_UNIX
        pthread_mutex_t printLock = PTHREAD_MUTEX_INITIALIZER;
#else
        CRITICAL_SECTION printLock;
#endif



// Prepares the lock that serializes output from the worker threads.
void printLockInit()
{
#ifndef OS_UNIX
	InitializeCriticalSection(&printLock);
#endif
}



// Releases the print lock.
void printLockDestroy()
{
#ifndef OS_UNIX
	DeleteCriticalSection(&printLock);
#endif
}



// Prints a message without interleaving it with another thread's output.
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



// Loads Luna cryptoki library
void loadLunaLibrary()
{
	CK_C_GetFunctionList C_GetFunctionList = NULL;

	char *libPath = getenv("P11_LIB"); // P11_LIB is the complete path of Cryptoki library.
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



// Unloads the cryptoki library and frees the memory allocated for the slot password.
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



// Checks the return value of a pkcs#11 function and exits if it failed.
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		printf("%s failed with 0x%lx\n\n", message, rv);
		if(p11Func!=NULL) p11Func->C_Finalize(NULL_PTR);
		exit(1);
	}
}



// Connects to a Luna slot and logs in as crypto officer.
void connectToLunaSlot()
{
	checkOperation(p11Func->C_Initialize(NULL), "C_Initialize");
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &hSession), "C_OpenSession");
	checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen((const char*)slotPin)), "C_Login");
	printf("\n> Connected to Luna.\n");
	printf("--> SLOT ID : %lu.\n", slotId);
	printf("--> SESSION ID : %lu.\n", hSession);
}



// Logs out and disconnects from the Luna slot.
void disconnectFromLunaSlot()
{
	checkOperation(p11Func->C_Logout(hSession), "C_Logout");
	checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
	checkOperation(p11Func->C_Finalize(NULL), "C_Finalize");
	printf("\n> Disconnected from Luna slot.\n\n");
}



// Selects the SLIP-10 curve named on the command line.
int selectCurve(const char *name)
{
	if(strcmp(name, "secp256k1")==0)
	{
		ecParam = oidSecp256k1;
		ecParamLen = sizeof(oidSecp256k1);
		curveIsEd25519 = 0;
		curveName = "secp256k1";
		return 0;
	}
	if(strcmp(name, "p256")==0)
	{
		ecParam = oidP256;
		ecParamLen = sizeof(oidP256);
		curveIsEd25519 = 0;
		curveName = "NIST P-256";
		return 0;
	}
	if(strcmp(name, "ed25519")==0)
	{
		ecParam = oidEd25519;
		ecParamLen = sizeof(oidEd25519);
		curveIsEd25519 = 1;
		curveName = "Ed25519";
		return 0;
	}
	return -1;
}



// Looks for a seed already stored on the token under the requested label.
// Returns CK_INVALID_HANDLE when the partition holds none.
CK_OBJECT_HANDLE findSeedKey()
{
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
	CK_ULONG objCount = 0;
	CK_ATTRIBUTE attrib[] =
	{
		{CKA_CLASS,	&objClass,	sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN,	&yes,		sizeof(CK_BBOOL)},
		{CKA_LABEL,	seedLabel,	(CK_ULONG)strlen((const char*)seedLabel)}
	};

	checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, sizeof(attrib)/sizeof(*attrib)), "C_FindObjectsInit");
	checkOperation(p11Func->C_FindObjects(hSession, &found, 1, &objCount), "C_FindObjects");
	checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
	return objCount ? found : CK_INVALID_HANDLE;
}



// Obtains the 32 byte generic secret that seeds the SLIP-10 tree.
// Without a seed label the secret is a session object, so every run builds a different tree.
// With one, an existing token seed is reused and only a first run has to generate it.
// The seed is marked non-extractable, so the only way it leaves the HSM is a backup or a clone.
void generateSeedKey()
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
	CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib) - 1; // the label slot stays unused by default

	if(seedLabel!=NULL)
	{
		seedKey = findSeedKey();
		if(seedKey!=CK_INVALID_HANDLE)
		{
			printf("\n> Seed \"%s\" found on the token. Handle : %lu\n", seedLabel, seedKey);
			printf("--> Every key below it matches the previous run.\n");
			return;
		}
		attrib[0].pValue = &yes;
		attrib[attribLen].pValue = seedLabel;
		attrib[attribLen].ulValueLen = (CK_ULONG)strlen((const char*)seedLabel);
		attribLen++;
	}

	checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &seedKey), "C_GenerateKey");
	if(seedLabel!=NULL)
		printf("\n> Seed generated and stored as \"%s\". Handle : %lu\n", seedLabel, seedKey);
	else
		printf("\n> Seed generated. Handle : %lu\n", seedKey);
}



// Formats CKA_BIP32_FINGERPRINT, the short identifier SLIP-10 computes from a key's public value.
// An object handle changes on every run, but a fingerprint depends only on the seed and the path,
// so it is what shows that two runs really did rebuild the same tree.
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



// Derives the SLIP-10 master keypair from the seed.
// CKA_ECDSA_PARAMS on both templates is what selects SLIP-10 instead of classic BIP-32.
void deriveMasterKeyPair()
{
	CK_BYTE keyLabelPub[] = "SLIP10-master-public";
	CK_BYTE keyLabelPri[] = "SLIP10-master-private";
	CK_KEY_TYPE keyType = CKK_BIP32;
	CK_BIP32_MASTER_DERIVE_PARAMS masterParam;
	CK_MECHANISM mech;
	CK_RV rv = CKR_OK;
	char fingerprint[40];

	CK_ATTRIBUTE attribPub[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,			&keyType,		sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,			keyLabelPub,		sizeof(keyLabelPub)-1},
		{CKA_PRIVATE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_BIP32_VERSION_BYTES,	versionBytesPub,	sizeof(versionBytesPub)},
		{CKA_ECDSA_PARAMS,		ecParam,		ecParamLen}
	};
	CK_ATTRIBUTE attribPri[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,			&keyType,		sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,			keyLabelPri,		sizeof(keyLabelPri)-1},
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

	// A partition below firmware 7.8.7 has no SLIP-10 support and rejects the templates above,
	// so name the likely cause rather than leaving the caller with a bare return code.
	rv = p11Func->C_DeriveKey(hSession, &mech, seedKey, NULL, 0, NULL);
	if(rv==CKR_ATTRIBUTE_TYPE_INVALID || rv==CKR_MECHANISM_INVALID)
		printf("\nSlot %lu rejected the SLIP-10 templates. SLIP-10 requires firmware 7.8.7 or newer.\n", slotId);
	checkOperation(rv, "C_DeriveKey");
	masterKeyPub = masterParam.hPublicKey;
	masterKeyPri = masterParam.hPrivateKey;
	fingerprintText(hSession, masterKeyPub, fingerprint, sizeof(fingerprint));
	printf("\n> SLIP-10 master keypair derived on %s.\n", curveName);
	printf("--> FINGERPRINT : %s\n", fingerprint);
	printf("--> PUBLIC KEY HANDLE : %lu\n", masterKeyPub);
	printf("--> PRIVATE KEY HANDLE : %lu\n", masterKeyPri);
}



// Thread entry point. Each thread owns a session and derives one child leaf of the master key.
#ifdef OS_UNIX
void *deriveChildKeyPair(void *arg)
#else
DWORD WINAPI deriveChildKeyPair(LPVOID arg)
#endif
{
	int childIndex = (int)(intptr_t)arg;
	CK_SESSION_HANDLE session = 0;
	CK_KEY_TYPE keyType = CKK_BIP32;
	CK_BYTE keyLabelPub[64];
	CK_BYTE keyLabelPri[64];
	CK_BIP32_CHILD_DERIVE_PARAMS childParam;
	CK_MECHANISM mech;
	CK_ULONG path[5];
	CK_RV rv = CKR_OK;
	char message[200];
	char fingerprint[40];

	sprintf((char*)keyLabelPub, "SLIP10-child-%d-public", childIndex);
	sprintf((char*)keyLabelPri, "SLIP10-child-%d-private", childIndex);

	CK_ATTRIBUTE attribPub[] =
	{
		{CKA_TOKEN,			&no,			sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,			&keyType,		sizeof(CK_KEY_TYPE)},
		{CKA_LABEL,			keyLabelPub,		strlen((const char*)keyLabelPub)},
		{CKA_PRIVATE,			&yes,			sizeof(CK_BBOOL)},
		{CKA_VERIFY,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&no,			sizeof(CK_BBOOL)},
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
		{CKA_SIGN,			&yes,			sizeof(CK_BBOOL)},
		{CKA_DERIVE,			&no,			sizeof(CK_BBOOL)},
		{CKA_BIP32_VERSION_BYTES,	versionBytesPri,	sizeof(versionBytesPri)},
		{CKA_ECDSA_PARAMS,		ecParam,		ecParamLen}
	};

	// BIP-44 path m/44'/0'/0'/change/address, with a different address index per thread.
	// Ed25519 cannot derive a child from a public key, so its path is hardened all the way down.
	path[0] = CKF_BIP32_HARDENED | CKG_BIP44_PURPOSE;
	path[1] = CKF_BIP32_HARDENED | CKG_BIP44_COIN_TYPE_BTC;
	path[2] = CKF_BIP32_HARDENED | 0;
	if(curveIsEd25519)
	{
		path[3] = CKF_BIP32_HARDENED | CKG_BIP32_EXTERNAL_CHAIN;
		path[4] = CKF_BIP32_HARDENED | (CK_ULONG)childIndex;
	}
	else
	{
		path[3] = CKG_BIP32_EXTERNAL_CHAIN;
		path[4] = (CK_ULONG)childIndex;
	}

	memset(&childParam, 0, sizeof(childParam));
	childParam.pPublicKeyTemplate = attribPub;
	childParam.ulPublicKeyAttributeCount = sizeof(attribPub) / sizeof(*attribPub);
	childParam.pPrivateKeyTemplate = attribPri;
	childParam.ulPrivateKeyAttributeCount = sizeof(attribPri) / sizeof(*attribPri);
	childParam.pulPath = path;
	childParam.ulPathLen = sizeof(path) / sizeof(*path); // Number of path elements, not bytes.
	childParam.hPublicKey = CK_INVALID_HANDLE;
	childParam.hPrivateKey = CK_INVALID_HANDLE;

	mech.mechanism = CKM_BIP32_CHILD_DERIVE;
	mech.pParameter = &childParam;
	mech.ulParameterLen = sizeof(childParam);

	rv = p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &session);
	if(rv!=CKR_OK)
	{
		sprintf(message, "--> Child %d : C_OpenSession failed with 0x%lx\n", childIndex, rv);
		lockedPrint(message);
#ifdef OS_UNIX
		return (void*)(intptr_t)1;
#else
		return 1;
#endif
	}

	rv = p11Func->C_DeriveKey(session, &mech, masterKeyPri, NULL, 0, NULL);
	if(rv!=CKR_OK)
	{
		sprintf(message, "--> Child %d : C_DeriveKey failed with 0x%lx\n", childIndex, rv);
		lockedPrint(message);
		p11Func->C_CloseSession(session);
#ifdef OS_UNIX
		return (void*)(intptr_t)1;
#else
		return 1;
#endif
	}

	fingerprintText(session, childParam.hPublicKey, fingerprint, sizeof(fingerprint));
	sprintf(message, "--> Child %d : derived. FINGERPRINT : %s, PUBLIC KEY HANDLE : %lu, PRIVATE KEY HANDLE : %lu\n",
		childIndex, fingerprint, childParam.hPublicKey, childParam.hPrivateKey);
	lockedPrint(message);
	p11Func->C_CloseSession(session);
#ifdef OS_UNIX
	return (void*)(intptr_t)0;
#else
	return 0;
#endif
}



// Prints the syntax for executing this code.
void usage(const char *exeName)
{
	printf("\nUsage :-\n");
	printf("%s <slot_number> <crypto_officer_password> <curve> <number_of_children> [seed_label]\n\n", exeName);
	printf("curve : secp256k1 | p256 | ed25519\n");
	printf("--> Ed25519 paths are hardened at every level, as required by SLIP-10.\n");
	printf("--> Requires Luna firmware 7.8.7 or newer.\n");
	printf("--> seed_label is optional. Without it the seed is a session object and every run\n");
	printf("    builds a different tree. With it the seed is kept on the token, so a later run\n");
	printf("    with the same label rebuilds the identical tree.\n\n");
	printf("Example :-\n");
	printf("%s 0 userpin ed25519 4\n", exeName);
	printf("%s 0 userpin ed25519 4 my-slip10-seed\n\n", exeName);
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

	nChildren = atoi(argv[4]);
	if(nChildren<1)
	{
		printf("\nnumber_of_children must be greater than zero.\n");
		usage(argv[0]);
		free(slotPin);
		exit(1);
	}

	if(argc==6) seedLabel = (CK_BYTE*)argv[5];

	printLockInit();
	loadLunaLibrary();
	connectToLunaSlot();
	generateSeedKey();
	deriveMasterKeyPair();
	printf("\n> Deriving %d child keypair(s), one per thread.\n\n", nChildren);

#ifdef OS_UNIX
	{
		pthread_t *threads = (pthread_t*)malloc(nChildren * sizeof(pthread_t));
		for(ctr=0; ctr<nChildren; ctr++)
			pthread_create(&threads[ctr], NULL, deriveChildKeyPair, (void*)(intptr_t)ctr);

		for(ctr=0; ctr<nChildren; ctr++)
		{
			void *threadReturn = 0;
			pthread_join(threads[ctr], &threadReturn);
			if((intptr_t)threadReturn!=0) failed++;
		}
		free(threads);
	}
#else
	{
		HANDLE *threads = (HANDLE*)malloc(nChildren * sizeof(HANDLE));
		for(ctr=0; ctr<nChildren; ctr++)
			threads[ctr] = CreateThread(NULL, 0, deriveChildKeyPair, (LPVOID)(intptr_t)ctr, 0, NULL);

		// Joined one at a time because WaitForMultipleObjects accepts at most 64 handles.
		for(ctr=0; ctr<nChildren; ctr++)
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

	printf("\n> %d of %d child keypair(s) derived.\n", nChildren-failed, nChildren);
	if(seedLabel!=NULL)
		printf("\n> Seed \"%s\" stays on the token. Run again with the same label to rebuild this tree.\n", seedLabel);
	disconnectFromLunaSlot();
	printLockDestroy();
	freeMem();
	return (failed==0) ? 0 : 1;
}
