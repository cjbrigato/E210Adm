#pragma once

#include <fstream>
#include <vector>
//#include <windows.h>
#include "../lib/minizip/ioapi_mem.h"
#include "../lib/minizip/unzip.h"

typedef unsigned char BYTE;

#include <iostream>

#define PWDMAXLEN 0x77
#define PWDMAXBYTE 0x7f

const uint8_t kDefaultMaxPasswordLenght = 0x77;
const uint8_t kDefaultXorKeyOffset = kDefaultMaxPasswordLenght;
const uint8_t kMaxAsciiCharValue = 0x7f;

struct ZoSEncryptionDescriptor {

    uint16_t mRawDescriptorLen = PWDMAXLEN;
    unsigned char mRawDescriptor[PWDMAXLEN + 4] = {0};
    uint16_t mPasswordLen = 0;
    unsigned char *mEncryptedPassword;
    unsigned char mPlainTextPassword[PWDMAXLEN] = {0};

    /*static void ZoSMungeToAscii(unsigned char *pEncString) {
        for (int i = 0; i < strnlen((const char *)pEncString, kDefaultMaxPasswordLenght); i++) {
            pEncString[i] += (1 << (i % (CHAR_BIT * sizeof(int)))) ^ pEncString[kDefaultXorKeyOffset];
            for (int j = 8; j > 0; j--) {
                pEncString[i] &= ~(1 << (j));
                if (pEncString[i] < kMaxAsciiCharValue)
                    break;
            }
            if (pEncString[i] < 0x21) {
                // pEncString[i] |= 1 << (pEncString[i] + 5 - pEncString[i] / 3);
                // pEncString[i]++;
                pEncString[i] = ((1 << ((pEncString[i] % 3) + 5)) | pEncString[i]) + 1;
            }
        }
    }*/

    static void ZoSMungeToAscii(unsigned char *pEncString, uint8_t XorKeyOffset = kDefaultXorKeyOffset,
                                uint8_t MaxPasswordLenght = kDefaultMaxPasswordLenght) {
        for (int i = 0; i < strnlen((const char *)pEncString, MaxPasswordLenght); i++) {
            pEncString[i] = (1 << (i % (CHAR_BIT * sizeof(int)))) + pEncString[i] ^ pEncString[XorKeyOffset];
            for (int j = 8; j > 0; j--) {
                pEncString[i] &= ~(1 << (j));
                if (pEncString[i] < kMaxAsciiCharValue)
                    break;
            }
            if (pEncString[i] < 0x21) {
                // pEncString[i] |= 1 << (pEncString[i] + 5 - pEncString[i] / 3);
                // pEncString[i]++;
                pEncString[i] = ((1 << ((pEncString[i] % 3) + 5)) | pEncString[i]) + 1;
            }
        }
    }

    static int32_t _Unzipper_MungeBufferToAscii(char *a1, int32_t a2) {
        // 0x4eee3
        if (a2 < 2) {
            // 0x4ef91
            *(char *)a1 = 0;
            return 1;
        }
        char v1 = *(char *)a1; // 0x4eefb
        if (v1 == 0) {
            // 0x4ef91
            *(char *)a1 = 0;
            return 1;
        }
        uint32_t v2 = a2 - 1;                                                      // 0x4ef05
        int32_t v3 = 0;                                                            // 0x4ef0a
        int32_t v4 = (1 << v3 % 32) + (int32_t)v1 ^ (int32_t) * (char *)(v2 + a1); // 0x4ef1e
        int32_t v5 = v4 % 256;                                                     // 0x4ef20
        int32_t v6 = v5;                                                           // 0x4ef26
        int32_t v7 = v4;                                                           // 0x4ef26
        int32_t v8 = v5;                                                           // 0x4ef26
        int32_t v9;                                                                // 0x4eee3
        uint32_t v10;                                                              // 0x4eee3
        int32_t v11;                                                               // 0x4ef38
        if (v5 >= 127) {
            v10 = 8;
            v11 = (0xfffffffe >> 32 - v10 | -2 << v10) & v6;
            v7 = v11;
            v8 = v11;
            while (v10 >= 2) {
                // 0x4ef3f
                v9 = v10 - 1;
                v6 = v11;
                v7 = v11;
                v8 = v11;
                if (v11 < 127) {
                    // break -> 0x4ef4b
                    break;
                }
                v10 = v9;
                v11 = (0xfffffffe >> 32 - v10 | -2 << v10) & v6;
                v7 = v11;
                v8 = v11;
            }
        }
        uint32_t v12 = v8;
        int32_t v13 = v7;
        int32_t v14 = v13; // 0x4ef4e
        if (v12 < 33) {
            // 0x4ef50
            v14 = (1 << (v12 + 5 - v12 / 3) % 32 | v13) % 256 + 1;
        }
        // 0x4ef6f
        *(char *)a1 = (char)v14;
        v3++;
        uint64_t v15 = uint64_t(a1 + v3); // 0x4ef7a
        while (v3 < v2) {
            char v16 = *(char *)v15; // 0x4ef85
            if (v16 == 0) {
                // break -> 0x4ef91
                break;
            }
            v4 = (1 << v3 % 32) + (int32_t)v16 ^ (int32_t) * (char *)(v2 + a1);
            v5 = v4 % 256;
            v6 = v5;
            v7 = v4;
            v8 = v5;
            if (v5 >= 127) {
                v10 = 8;
                v11 = (0xfffffffe >> 32 - v10 | -2 << v10) & v6;
                v7 = v11;
                v8 = v11;
                while (v10 >= 2) {
                    // 0x4ef3f
                    v9 = v10 - 1;
                    v6 = v11;
                    v7 = v11;
                    v8 = v11;
                    if (v11 < 127) {
                        // break -> 0x4ef4b
                        break;
                    }
                    v10 = v9;
                    v11 = (0xfffffffe >> 32 - v10 | -2 << v10) & v6;
                    v7 = v11;
                    v8 = v11;
                }
            }
            // 0x4ef4b
            v12 = v8;
            v13 = v7;
            v14 = v13;
            if (v12 < 33) {
                // 0x4ef50
                v14 = (1 << (v12 + 5 - v12 / 3) % 32 | v13) % 256 + 1;
            }
            // 0x4ef6f
            *(char *)v15 = (char)v14;
            v3++;
            v15 = (int64_t)(a1 + v3); // 0x4ef7a
        }
        // 0x4ef91
        *(char *)v15 = 0;
        return 1;
    }

    ZoSEncryptionDescriptor(unsigned char *pEncPasswordString, uint16_t len) {
        if (len >= PWDMAXLEN)
            return;
        mRawDescriptorLen = len + 4;
        mPasswordLen = len;
        memset(mRawDescriptor, 0, mRawDescriptorLen);
        for (int i = 0; i <= mPasswordLen; i++) {
            mRawDescriptor[i + 4] = pEncPasswordString[i];
        }
        mEncryptedPassword = &mRawDescriptor[4];
        memset(mPlainTextPassword, 0, mPasswordLen + 1);
        for (int i = 0; i <= mPasswordLen; i++) {
            mPlainTextPassword[i] = mEncryptedPassword[i];
        }
        //_Unzipper_MungeBufferToAscii((char *)mPlainTextPassword, 0x78);
        ZoSMungeToAscii(mPlainTextPassword);
    }

    ZoSEncryptionDescriptor(unzFile uf) {

        char filename_inzip[256] = {0};
        unz_file_info64 file_info = {0};
        unsigned char extrafield[kDefaultMaxPasswordLenght + 4] = {0};
        uint16_t extrafield_size = kDefaultMaxPasswordLenght + 4;

        int err = unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip), (void *)extrafield,
                                          extrafield_size, NULL, 0);
        if (err != UNZ_OK) {
            printf("!error %d with zipfile in unzGetCurrentFileInfo\n", err);
            return;
        }

        mRawDescriptorLen = file_info.size_file_extra;
        for (int i = 0; i < mRawDescriptorLen; i++) {
            mRawDescriptor[i] = extrafield[i];
        }
        mEncryptedPassword = &mRawDescriptor[4];
        unsigned char encsize[2] = {mRawDescriptor[2], mRawDescriptor[3]};
        mPasswordLen = *(uint16_t *)&encsize;
        memset(mPlainTextPassword, 0, mPasswordLen + 1);
        for (int i = 0; i <= mPasswordLen; i++) {
            mPlainTextPassword[i] = mEncryptedPassword[i];
        }

        ZoSMungeToAscii(mPlainTextPassword);
    }
};
