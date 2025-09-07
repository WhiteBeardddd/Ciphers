#ifndef WINDOW_GUI_H
#define WINDOW_GUI_H

#include <windows.h>
#include "aescrypto.h"

#define ID_INPUT_WORD        1001
#define ID_ENCRYPT_BTN       1002
#define ID_ENCRYPTED_TEXT    1003
#define ID_ORIGINAL_HASH     1004
#define ID_INPUT_DECRYPT     1005
#define ID_DECRYPT_BTN       1006
#define ID_DECRYPTED_TEXT    1007
#define ID_DECRYPTED_HASH    1008
#define ID_COMPARISON_RESULT 1009

extern HWND hInputWord, hEncryptBtn, hEncryptedText, hOriginalHash;
extern HWND hInputDecrypt, hDecryptBtn, hDecryptedText, hDecryptedHash;
extern HWND hComparisonResult;
extern char originalWord[256];
extern char originalWordHash[64];
extern HBRUSH hWhiteBrush;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif
