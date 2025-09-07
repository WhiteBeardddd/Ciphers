#include "aescrypto.h"
#include <wincrypt.h>
#include <string.h>


#define KEYLENGTH 256
#define ENCRYPT_ALGORITHM CALG_AES_256
#define IV_SIZE 16


BYTE keyBytes[32] = {
    // Example hardcoded key (32 bytes for AES-256)
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};


BYTE iv[IV_SIZE] = { 0 };  // Can be randomized and stored if needed


int encryptAES(const BYTE* plaintext, DWORD plaintextLen, BYTE* ciphertext, DWORD* ciphertextLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[512];
    DWORD bufferLen = plaintextLen;
    memcpy(buffer, plaintext, plaintextLen);


    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;


    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return 0;
    if (!CryptHashData(hHash, keyBytes, sizeof(keyBytes), 0)) return 0;


    if (!CryptDeriveKey(hProv, ENCRYPT_ALGORITHM, hHash, CRYPT_EXPORTABLE, &hKey)) return 0;


    CryptSetKeyParam(hKey, KP_IV, iv, 0);


    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer, &bufferLen, sizeof(buffer))) return 0;


    memcpy(ciphertext, buffer, bufferLen);
    *ciphertextLen = bufferLen;


    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);


    return 1;
}


int decryptAES(const BYTE* ciphertext, DWORD ciphertextLen, BYTE* plaintext, DWORD* plaintextLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[512];
    DWORD bufferLen = ciphertextLen;
    memcpy(buffer, ciphertext, ciphertextLen);


    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;


    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return 0;
    if (!CryptHashData(hHash, keyBytes, sizeof(keyBytes), 0)) return 0;


    if (!CryptDeriveKey(hProv, ENCRYPT_ALGORITHM, hHash, CRYPT_EXPORTABLE, &hKey)) return 0;


    CryptSetKeyParam(hKey, KP_IV, iv, 0);


    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer, &bufferLen)) return 0;


    memcpy(plaintext, buffer, bufferLen);
    *plaintextLen = bufferLen;
    plaintext[bufferLen] = '\0';


    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);


    return 1;
}


unsigned long hash(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}