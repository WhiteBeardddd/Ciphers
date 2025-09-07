#include "windowgui.h"
#include <string.h>
#include <stdio.h>

// Define globals here
HWND hInputWord, hEncryptBtn, hEncryptedText, hOriginalHash;
HWND hInputDecrypt, hDecryptBtn, hDecryptedText, hDecryptedHash;
HWND hComparisonResult;
char originalWord[256];
char originalWordHash[64];
HBRUSH hWhiteBrush;

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            hWhiteBrush = CreateSolidBrush(RGB(255, 255, 255));  // White background

            CreateWindow("STATIC", "Enter word to encrypt:", WS_VISIBLE | WS_CHILD,
                         10, 10, 200, 20, hwnd, NULL, NULL, NULL);
            hInputWord = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                      10, 35, 300, 25, hwnd, (HMENU)ID_INPUT_WORD, NULL, NULL);

            hEncryptBtn = CreateWindow("BUTTON", "Encrypt", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                       320, 35, 80, 25, hwnd, (HMENU)ID_ENCRYPT_BTN, NULL, NULL);

            CreateWindow("STATIC", "Encrypted text (hex):", WS_VISIBLE | WS_CHILD,
                         10, 70, 200, 20, hwnd, NULL, NULL, NULL);
            hEncryptedText = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
                                          10, 95, 390, 25, hwnd, (HMENU)ID_ENCRYPTED_TEXT, NULL, NULL);

            CreateWindow("STATIC", "Original hash:", WS_VISIBLE | WS_CHILD,
                         10, 130, 200, 20, hwnd, NULL, NULL, NULL);
            hOriginalHash = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
                                         10, 155, 390, 25, hwnd, (HMENU)ID_ORIGINAL_HASH, NULL, NULL);

            CreateWindow("STATIC", "----------------------------------------", WS_VISIBLE | WS_CHILD,
                         10, 190, 400, 20, hwnd, NULL, NULL, NULL);

            CreateWindow("STATIC", "Enter hex text to decrypt:", WS_VISIBLE | WS_CHILD,
                         10, 215, 200, 20, hwnd, NULL, NULL, NULL);
            hInputDecrypt = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                         10, 240, 300, 25, hwnd, (HMENU)ID_INPUT_DECRYPT, NULL, NULL);

            hDecryptBtn = CreateWindow("BUTTON", "Decrypt", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                       320, 240, 80, 25, hwnd, (HMENU)ID_DECRYPT_BTN, NULL, NULL);

            CreateWindow("STATIC", "Decrypted text:", WS_VISIBLE | WS_CHILD,
                         10, 275, 200, 20, hwnd, NULL, NULL, NULL);
            hDecryptedText = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
                                          10, 300, 390, 25, hwnd, (HMENU)ID_DECRYPTED_TEXT, NULL, NULL);

            CreateWindow("STATIC", "Decrypted hash:", WS_VISIBLE | WS_CHILD,
                         10, 335, 200, 20, hwnd, NULL, NULL, NULL);
            hDecryptedHash = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
                                          10, 360, 390, 25, hwnd, (HMENU)ID_DECRYPTED_HASH, NULL, NULL);

            CreateWindow("STATIC", "Comparison result:", WS_VISIBLE | WS_CHILD,
                         10, 395, 200, 20, hwnd, NULL, NULL, NULL);
            hComparisonResult = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY,
                                             10, 420, 390, 25, hwnd, (HMENU)ID_COMPARISON_RESULT, NULL, NULL);
            break;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT: {
            HDC hdcStatic = (HDC)wParam;
            SetBkColor(hdcStatic, RGB(255, 255, 255));
            SetTextColor(hdcStatic, RGB(0, 0, 0));
            return (INT_PTR)hWhiteBrush;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_ENCRYPT_BTN: {
                    char inputText[256];
                    BYTE encrypted[512];
                    DWORD encryptedLen;
                    char hexOutput[1024] = {0};

                    GetWindowText(hInputWord, inputText, sizeof(inputText));
                    if (strlen(inputText) > 0) {
                        strcpy(originalWord, inputText);
                        unsigned long hashValue = hash(inputText);
                        sprintf(originalWordHash, "%lu", hashValue);

                        if (encryptAES((BYTE*)inputText, strlen(inputText), encrypted, &encryptedLen)) {
                            // Convert binary to hex string
                            for (DWORD i = 0; i < encryptedLen; i++) {
                                sprintf(hexOutput + i * 2, "%02X", encrypted[i]);
                            }

                            SetWindowText(hEncryptedText, hexOutput);
                            SetWindowText(hOriginalHash, originalWordHash);
                            SetWindowText(hDecryptedText, "");
                            SetWindowText(hDecryptedHash, "");
                            SetWindowText(hComparisonResult, "");
                        } else {
                            SetWindowText(hEncryptedText, "Encryption failed!");
                        }
                    }
                    break;
                }

                case ID_DECRYPT_BTN: {
                    char inputText[512];
                    BYTE binaryInput[512];
                    DWORD binLen;
                    BYTE decrypted[512];
                    DWORD decryptedLen;
                    char hashStr[64];

                    GetWindowText(hInputDecrypt, inputText, sizeof(inputText));
                    size_t hexLen = strlen(inputText);
                    if (hexLen > 0 && hexLen % 2 == 0) {
                        binLen = (DWORD)(hexLen / 2);
                        for (DWORD i = 0; i < binLen; i++) {
                            sscanf(&inputText[i * 2], "%2hhx", &binaryInput[i]);
                        }

                        if (decryptAES(binaryInput, binLen, decrypted, &decryptedLen)) {
                            SetWindowText(hDecryptedText, (char*)decrypted);

                            unsigned long decryptedHash = hash((char*)decrypted);
                            sprintf(hashStr, "%lu", decryptedHash);
                            SetWindowText(hDecryptedHash, hashStr);

                            if (strlen(originalWordHash) > 0) {
                                if (strcmp(originalWordHash, hashStr) == 0) {
                                    SetWindowText(hComparisonResult, "MATCH - Decryption successful!");
                                } else {
                                    SetWindowText(hComparisonResult, "ERROR MISMATCH - Decryption failed!");
                                }
                            } else {
                                SetWindowText(hComparisonResult, "No original hash to compare with");
                            }
                        } else {
                            SetWindowText(hDecryptedText, "Decryption failed!");
                        }
                    } else {
                        SetWindowText(hComparisonResult, "Invalid hex input.");
                    }
                    break;
                }
            }
            break;

        case WM_DESTROY:
            DeleteObject(hWhiteBrush);  // Clean up
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
