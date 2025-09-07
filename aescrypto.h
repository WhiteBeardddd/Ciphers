#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H


#include <windows.h>


int encryptAES(const BYTE* plaintext, DWORD plaintextLen, BYTE* ciphertext, DWORD* ciphertextLen);
int decryptAES(const BYTE* ciphertext, DWORD ciphertextLen, BYTE* plaintext, DWORD* plaintextLen);
unsigned long hash(const char* str);


#endif