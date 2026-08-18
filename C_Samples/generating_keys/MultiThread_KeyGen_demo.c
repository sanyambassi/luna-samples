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
	- This sample demonstrates how to generate keys in bulk using a multi-threaded pkcs#11 application.
	- PKCS#11 has no bulk key generation call, so a large batch is simply many C_GenerateKey or C_GenerateKeyPair calls.
	- Key generation in a session is processed serially in Luna HSM, so a single-threaded batch leaves the HSM idle between calls.
	- This sample logs in once, then opens a session per thread and generates keys in parallel across those sessions.
	- Supported key types are AES-256, RSA-2048, ECDSA P-256 and Ed25519.
	- Keys are created as session objects (CKA_TOKEN=CK_FALSE) so that a large run does not fill up the partition.

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

CK_BBOOL yes = CK_TRUE;
CK_BBOOL no = CK_FALSE;

// Key types this sample can generate.
typedef enum
{
	ALG_AES = 0,
	ALG_RSA,
	ALG_ECDSA,
	ALG_EDDSA
} AlgType;

AlgType alg = ALG_AES;
int nThreads = 0;
int keysPerThread = 0;


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



// Translates the key type provided on the command line.
int parseAlg(const char *name)
{
	if(strcmp(name, "aes")==0) { alg = ALG_AES; return 0; }
	if(strcmp(name, "rsa")==0) { alg = ALG_RSA; return 0; }
	if(strcmp(name, "ecdsa")==0) { alg = ALG_ECDSA; return 0; }
	if(strcmp(name, "eddsa")==0) { alg = ALG_EDDSA; return 0; }
	return -1;
}



// Returns a printable name for the selected key type.
const char *algName()
{
	switch(alg)
	{
		case ALG_AES	: return "AES-256";
		case ALG_RSA	: return "RSA-2048";
		case ALG_ECDSA	: return "ECDSA P-256";
		case ALG_EDDSA	: return "Ed25519";
		default		: return "UNKNOWN";
	}
}



// Generates a single key or keypair of the selected type on the calling thread's session.
CK_RV generateOneKey(CK_SESSION_HANDLE session, int threadId, int keyIndex)
{
	char keyLabel[80];
	sprintf(keyLabel, "BulkKeyGen-t%d-%d", threadId, keyIndex);

	if(alg==ALG_AES)
	{
		CK_MECHANISM mech = {CKM_AES_KEY_GEN};
		CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
		CK_ULONG keyLen = 32;
		CK_OBJECT_HANDLE objHandle = 0;
		CK_ATTRIBUTE attrib[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_PRIVATE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,		&yes,			sizeof(CK_BBOOL)},
			{CKA_DECRYPT,		&yes,			sizeof(CK_BBOOL)},
			{CKA_CLASS,		&objClass,		sizeof(CK_OBJECT_CLASS)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)},
			{CKA_VALUE_LEN,		&keyLen,		sizeof(CK_ULONG)}
		};
		CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
		return p11Func->C_GenerateKey(session, &mech, attrib, attribLen, &objHandle);
	}

	if(alg==ALG_RSA)
	{
		CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN};
		CK_ULONG modulusBits = 2048;
		CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
		CK_OBJECT_HANDLE objHandlePub = 0, objHandlePri = 0;
		CK_ATTRIBUTE attribPub[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_VERIFY,		&yes,			sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,		&yes,			sizeof(CK_BBOOL)},
			{CKA_MODULUS_BITS,	&modulusBits,		sizeof(CK_ULONG)},
			{CKA_PUBLIC_EXPONENT,	publicExponent,		sizeof(publicExponent)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)}
		};
		CK_ATTRIBUTE attribPri[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_PRIVATE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SIGN,		&yes,			sizeof(CK_BBOOL)},
			{CKA_DECRYPT,		&yes,			sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,	&no,			sizeof(CK_BBOOL)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)}
		};
		CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);
		CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);
		return p11Func->C_GenerateKeyPair(session, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objHandlePub, &objHandlePri);
	}

	if(alg==ALG_ECDSA)
	{
		CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN};
		CK_BYTE ecParam[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}; // OID of secp256r1 (P-256).
		CK_OBJECT_HANDLE objHandlePub = 0, objHandlePri = 0;
		CK_ATTRIBUTE attribPub[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_VERIFY,		&yes,			sizeof(CK_BBOOL)},
			{CKA_EC_PARAMS,		ecParam,		sizeof(ecParam)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)}
		};
		CK_ATTRIBUTE attribPri[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_PRIVATE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SIGN,		&yes,			sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,	&no,			sizeof(CK_BBOOL)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)}
		};
		CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);
		CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);
		return p11Func->C_GenerateKeyPair(session, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objHandlePub, &objHandlePri);
	}

	// Ed25519.
	{
		CK_MECHANISM mech = {CKM_EC_EDWARDS_KEY_PAIR_GEN};
		CK_BYTE ecParam[] = {0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}; // OID of edwards25519, as used by GnuPG.
		CK_OBJECT_HANDLE objHandlePub = 0, objHandlePri = 0;
		CK_ATTRIBUTE attribPub[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_VERIFY,		&yes,			sizeof(CK_BBOOL)},
			{CKA_EC_PARAMS,		ecParam,		sizeof(ecParam)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)}
		};
		CK_ATTRIBUTE attribPri[] =
		{
			{CKA_TOKEN,		&no,			sizeof(CK_BBOOL)},
			{CKA_PRIVATE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,		&yes,			sizeof(CK_BBOOL)},
			{CKA_SIGN,		&yes,			sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,	&no,			sizeof(CK_BBOOL)},
			{CKA_LABEL,		keyLabel,		strlen(keyLabel)}
		};
		CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);
		CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);
		return p11Func->C_GenerateKeyPair(session, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objHandlePub, &objHandlePri);
	}
}



// Thread entry point. Each thread owns a session and generates keysPerThread keys on it.
#ifdef OS_UNIX
void *keyGenThread(void *arg)
#else
DWORD WINAPI keyGenThread(LPVOID arg)
#endif
{
	int threadId = (int)(intptr_t)arg;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv = CKR_OK;
	char message[160];
	int ctr = 0;

	rv = p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &session);
	if(rv!=CKR_OK)
	{
		sprintf(message, "--> Thread %d : C_OpenSession failed with 0x%lx\n", threadId, rv);
		lockedPrint(message);
#ifdef OS_UNIX
		return (void*)(intptr_t)1;
#else
		return 1;
#endif
	}

	for(ctr=0; ctr<keysPerThread; ctr++)
	{
		rv = generateOneKey(session, threadId, ctr);
		if(rv!=CKR_OK)
		{
			sprintf(message, "--> Thread %d : key %d failed with 0x%lx\n", threadId, ctr, rv);
			lockedPrint(message);
			p11Func->C_CloseSession(session);
#ifdef OS_UNIX
			return (void*)(intptr_t)1;
#else
			return 1;
#endif
		}
	}

	p11Func->C_CloseSession(session);
	sprintf(message, "--> Thread %d : generated %d %s key(s).\n", threadId, keysPerThread, algName());
	lockedPrint(message);
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
	printf("%s <slot_number> <crypto_officer_password> <key_type> <number_of_threads> <keys_per_thread>\n\n", exeName);
	printf("key_type : aes | rsa | ecdsa | eddsa\n");
	printf("--> aes   : AES-256 keys.\n");
	printf("--> rsa   : RSA-2048 keypairs.\n");
	printf("--> ecdsa : ECDSA keypairs on P-256.\n");
	printf("--> eddsa : Ed25519 keypairs.\n\n");
	printf("Example :-\n");
	printf("%s 0 userpin aes 4 10\n\n", exeName);
}



int main(int argc, char *argv[])
{
	int failed = 0;
	int ctr = 0;

	printf("\n%s\n", argv[0]);
	if(argc!=6)
	{
		usage(argv[0]);
		exit(1);
	}

	slotId = atoi(argv[1]);
	slotPin = (CK_BYTE*)malloc(strlen(argv[2]) + 1);
	strcpy((char*)slotPin, argv[2]);

	if(parseAlg(argv[3])!=0)
	{
		printf("\nUnsupported key type : %s\n", argv[3]);
		usage(argv[0]);
		free(slotPin);
		exit(1);
	}

	nThreads = atoi(argv[4]);
	keysPerThread = atoi(argv[5]);
	if(nThreads<1 || keysPerThread<1)
	{
		printf("\nnumber_of_threads and keys_per_thread must both be greater than zero.\n");
		usage(argv[0]);
		free(slotPin);
		exit(1);
	}

	printLockInit();
	loadLunaLibrary();
	connectToLunaSlot();
	printf("\n> Generating %d %s key(s) using %d thread(s).\n\n", nThreads*keysPerThread, algName(), nThreads);

#ifdef OS_UNIX
	{
		pthread_t *threads = (pthread_t*)malloc(nThreads * sizeof(pthread_t));
		for(ctr=0; ctr<nThreads; ctr++)
			pthread_create(&threads[ctr], NULL, keyGenThread, (void*)(intptr_t)ctr);

		for(ctr=0; ctr<nThreads; ctr++)
		{
			void *threadReturn = 0;
			pthread_join(threads[ctr], &threadReturn);
			if((intptr_t)threadReturn!=0) failed++;
		}
		free(threads);
	}
#else
	{
		HANDLE *threads = (HANDLE*)malloc(nThreads * sizeof(HANDLE));
		for(ctr=0; ctr<nThreads; ctr++)
			threads[ctr] = CreateThread(NULL, 0, keyGenThread, (LPVOID)(intptr_t)ctr, 0, NULL);

		// Joined one at a time because WaitForMultipleObjects accepts at most 64 handles.
		for(ctr=0; ctr<nThreads; ctr++)
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

	printf("\n> %d of %d thread(s) completed successfully.\n", nThreads-failed, nThreads);
	disconnectFromLunaSlot();
	printLockDestroy();
	freeMem();
	return (failed==0) ? 0 : 1;
}
