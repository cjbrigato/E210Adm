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
                pEncString[i] = ((1 << ((pEncString[i] % 3) + 5)) | pEncString[i]) + 1;
            }
        }
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
