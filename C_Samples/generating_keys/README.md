### SAMPLES FOR GENERATING KEYS.

| FILE_NAME | DESCRIPTION |
| --- | --- |
| CKM_AES_KEY_GEN_demo.c | demonstrates how to generate an AES key. |
| CKM_DES3_KEY_GEN_demo.c | demonstrates how to generate a DES-3 key. |
| CKM_EC_KEY_PAIR_GEN_demo.c | demonstrates how to generate ECDSA keypair. |
| CKM_PKCS5_PBKD2_demo.c | demonstrates how to derive AES key using PBKDF2. |
| CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN_demo.c | demonstrates how to generate RSA keypair using CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN mechanism. |
| CKM_RSA_PKCS_KEY_PAIR_GEN_demo.c | demonstrates how to generate RSA keypair. |
| CKM_SHA256_KEY_DERIVATION_demo.c | demonstrates how to derive key using CKM_SHA256_KEY_DERIVATION. |
| CKM_NIST_PRF_KDF_demo.c | demonstrates how to derive key using CKM_NIST_PRF_KDF_Demo |
| CKM_ECDH1_DERIVE_demo.c | demonstrates key exchange using CKM_ECDH1_DERIVE |
| CKM_EC_EDWARDS_KEY_PAIR_GEN_demo.c | demonstrates how to generate EDDSA keypair. |
| MultiThread_KeyGen_demo.c | demonstrates how to generate AES, RSA, ECDSA or EDDSA keys in bulk using multiple threads. |
| SLIP10_Derive_demo.c | demonstrates SLIP-10 key derivation using CKM_BIP32_MASTER_DERIVE and CKM_BIP32_CHILD_DERIVE. An optional seed label keeps the seed on the token, so a later run rebuilds the identical tree. |

For help with compiling and executing the code, please refer to the HOW_TO guide provided here : [HOW_TO](/C_Samples/HOW_TO.md).
