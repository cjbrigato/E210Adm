#pragma once

#include <fstream>
#include <iostream>
#include <vector>
//#include <windows.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#endif

#include "../lib/minizip/unzip.h"

#ifdef _WIN32
#define USEWIN32IOAPI
#include "iowin32.h"
#endif

#include "../lib/minizip/ioapi_mem.h"
#include "../lib/minizip/minishared.h"

#include "ZoSEncryptionDescriptor.h"

struct SsnExtractConf {
    const char *zipfilename = NULL;
    const char *filename_to_extract = NULL;
    int opt_do_list = 0;
    int opt_do_extract = 1;
    int opt_do_extract_withoutpath = 0;
    int opt_overwrite = 0;
    int opt_extractdir = 0;
    const char *dirname = NULL;
};

struct SsnZipFile {

    ourmemory_t mUnzmem = {0};
    zlib_filefunc_def mFilefunc32 = {0};
    int mOffset = 0x3e0;
    unzFile mUf;
    int mLastUnzError = UNZ_OK;

    static unsigned int FindPattern(char *memblock, unsigned int size, const char *pattern, size_t len) {
        unsigned int retval = 0;
        for (unsigned int i = 0; i < size; i++) {
            char checkByte = memblock[i];
            if (checkByte == pattern[0]) {
                if (!memcmp((void *)(memblock + i), pattern, len)) {
                    retval = i;
                    break;
                }
            }
        }
        return retval;
    }

    inline std::vector<uint8_t> RaiiRead(std::string file_path) {
        std::ifstream instream(file_path, std::ios::in | std::ios::binary);
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());
        return data;
    }

    void ParsePEFile2(std::string filename) {
        std::vector<uint8_t> memblock;
        memblock = RaiiRead(filename);
        mOffset = FindPattern((char *)&memblock[0], memblock.size(), "\x50\x4B\x03\x04", 4);
        if (!mOffset) {
            printf("PANIC: did not found any embedded ZIpFile. Are you properly targetting a ZoS SSN Patcher PE "
                   "File ?\n");
            exit(217);
        }
        printf("  --> Found Embedded ZipFile start at 0x%04X\n", mOffset);
        mUnzmem.size = memblock.size() - mOffset;
        mUnzmem.base = (char *)malloc(mUnzmem.size);
        memcpy(mUnzmem.base, &memblock[0] + mOffset, mUnzmem.size);
        fill_memory_filefunc(&mFilefunc32, &mUnzmem);
        mUf = unzOpen2("__notused__", &mFilefunc32);
    }

    void ParsePEFile(const char *filename) {
        std::ifstream file(filename, std::ios::in | std::ios::binary | std::ios::ate);
        printf("  -> %s\n", filename);
        if (file.is_open()) {

            std::streampos size = file.tellg();
            char *memblock = new char[size];
            file.seekg(0, std::ios::beg);
            file.read(memblock, size);
            file.close();

            // Our methods to parse for ZIP Header is wrong if the file starts with said header
            // So we first checkk for such immediate header, then we'll try to find such pattern if we fail.
            char FileStart[4] = {memblock[0], memblock[1], memblock[2], memblock[3]};
            unsigned int ZipStart = *(unsigned int *)&FileStart;

            if (ZipStart != 0x04034B50) {
                mOffset = FindPattern(memblock, size, "\x50\x4B\x03\x04", 4);
                if (!mOffset) {
                    printf(
                        "PANIC: did not found any embedded ZIpFile. Are you properly targetting a ZoS SSN Patcher PE "
                        "File ?\n");
                    exit(217);
                }
            } else {
                mOffset = 0;
            }

            printf("  --> Found Embedded ZipFile start at 0x%04X\n", mOffset);

            mUnzmem.size = (uint32_t)size - mOffset;
            mUnzmem.base = (char *)malloc(mUnzmem.size);
            memcpy(mUnzmem.base, memblock + mOffset, mUnzmem.size);

            delete[] memblock;

            fill_memory_filefunc(&mFilefunc32, &mUnzmem);

            mUf = unzOpen2("__notused__", &mFilefunc32);
        }
    }

    /* Borrowed from miniunz by Gilles Vollant*/
    int ListFilesInZip() {

        mLastUnzError = unzGoToFirstFile(mUf);
        if (mLastUnzError != UNZ_OK) {
            printf("error %d with zipfile in unzGoToFirstFile\n", mLastUnzError);
            return 1;
        }

        printf("  Length  Method     Size Ratio   Date    Time   CRC-32     Name\n");
        printf("  ------  ------     ---- -----   ----    ----   ------     ----\n");

        do {
            char filename_inzip[256] = {0};
            unz_file_info64 file_info = {0};
            uint32_t ratio = 0;
            struct tm tmu_date = {0};
            const char *string_method = NULL;
            char char_crypt = ' ';

            mLastUnzError =
                unzGetCurrentFileInfo64(mUf, &file_info, filename_inzip, sizeof(filename_inzip), NULL, 0, NULL, 0);
            if (mLastUnzError != UNZ_OK) {
                printf("error %d with zipfile in unzGetCurrentFileInfo\n", mLastUnzError);
                break;
            }

            if (file_info.uncompressed_size > 0)
                ratio = (uint32_t)((file_info.compressed_size * 100) / file_info.uncompressed_size);

            if ((file_info.flag & 1) != 0)
                char_crypt = '*';

            if (file_info.compression_method == 0)
                string_method = "Stored";
            else if (file_info.compression_method == Z_DEFLATED) {
                uint16_t level = (uint16_t)((file_info.flag & 0x6) / 2);
                if (level == 0)
                    string_method = "Defl:N";
                else if (level == 1)
                    string_method = "Defl:X";
                else if ((level == 2) || (level == 3))
                    string_method = "Defl:F"; /* 2:fast , 3 : extra fast*/
                else
                    string_method = "Unkn. ";
            } else if (file_info.compression_method == Z_BZIP2ED) {
                string_method = "BZip2 ";
            } else
                string_method = "Unkn. ";

            display_zpos64(file_info.uncompressed_size, 7);
            printf("  %6s%c", string_method, char_crypt);
            display_zpos64(file_info.compressed_size, 7);

            dosdate_to_tm(file_info.dos_date, &tmu_date);
            printf(" %3u%%  %2.2u-%2.2u-%2.2u  %2.2u:%2.2u  %8.8x   %s\n", ratio, (uint32_t)tmu_date.tm_mon + 1,
                   (uint32_t)tmu_date.tm_mday, (uint32_t)tmu_date.tm_year % 100, (uint32_t)tmu_date.tm_hour,
                   (uint32_t)tmu_date.tm_min, file_info.crc, filename_inzip);

            mLastUnzError = unzGoToNextFile(mUf);
        } while (mLastUnzError == UNZ_OK);

        if (mLastUnzError != UNZ_END_OF_LIST_OF_FILE && mLastUnzError != UNZ_OK) {
            printf("error %d with zipfile in unzGoToNextFile\n", mLastUnzError);
            return mLastUnzError;
        }

        return 0;
    }

    void GotoFirstFile() {
        mLastUnzError = unzGoToFirstFile(mUf);
        if (mLastUnzError != UNZ_OK) {
            printf("!error %d with zipfile in unzGoToFirstFile\n", mLastUnzError);
        }
    }

    void LocateFile(const char *inzipFile) {
        mLastUnzError = unzLocateFile(mUf, inzipFile, NULL);
        if (mLastUnzError != UNZ_OK) {
            printf("!error %d with zipfile in unzLocateFile\n", mLastUnzError);
        }
    }

    void GotoNextFile() {
        mLastUnzError = unzGoToNextFile(mUf);
        if (mLastUnzError != UNZ_END_OF_LIST_OF_FILE && mLastUnzError != UNZ_OK) {
            printf("error %d with zipfile in unzGoToNextFile\n", mLastUnzError);
        }
    }

    void ExtractAllFiles(int opt_extract_without_path, int *popt_overwrite) {
        GotoFirstFile();
        do {
            ExtractCurrentFile(opt_extract_without_path, popt_overwrite);
            if (mLastUnzError != UNZ_OK) {
                break;
            }
            GotoNextFile();
        } while (mLastUnzError == UNZ_OK);
    }

    static void HexDumpByteBuffer(unsigned char *dump, int msglen) {
        int msgbytesperline = 0x10;
        int totalhexlines = msglen / msgbytesperline;
        int fillbytes = msglen % msgbytesperline;
        if (fillbytes)
            totalhexlines++;
        int msgpos = 0;
        for (int line = 0; line < totalhexlines; line++) {
            msgpos = line * msgbytesperline;
            char linebuf[74];
            memset(linebuf, 0, sizeof(linebuf));
            printf("  %03X: ", msgpos);
            if (line < totalhexlines - 1 || !fillbytes) {
                for (int i = 0; i < msgbytesperline; i++) {
                    if ((dump[msgpos + i]) == 0) {
                        printf("00 ");
                    } else {
                        printf("%02X ", dump[msgpos + i]);
                    }
                }
                printf("| ");
                for (int i = 0; i < msgbytesperline; i++) {
                    if (isprint(dump[msgpos + i])) {
                        printf("%c", dump[msgpos + i]);
                    } else {
                        printf(".");
                    }
                }
            } else {
                int fillpos = msglen - msgpos;
                for (int i = 0; i < msgbytesperline; i++) {
                    if (i < fillpos) {
                        if ((dump[msgpos + i]) == 0) {
                            printf("00 ");
                        } else {
                            printf("%02X ", dump[msgpos + i]);
                        }
                    } else {
                        printf(".. ");
                    }
                }
                printf("| ");

                for (int i = 0; i < msgbytesperline; i++) {
                    if (i < fillpos) {
                        if (isprint(dump[msgpos + i])) {
                            printf("%c", dump[msgpos + i]);
                        } else {
                            printf(".");
                        }
                    } else {
                        printf(" ");
                    }
                }
            }
            printf(" \n");
        }
    }

    static void DisplayCurrentFileEncryptionDescriptor(bool plaintext, ZoSEncryptionDescriptor tEncryptionDescriptor) {

        unsigned char *dump;

        if (!plaintext) {
            printf("  * Password decryption : \n");
            dump = tEncryptionDescriptor.mEncryptedPassword;
        } else {
            dump = tEncryptionDescriptor.mPlainTextPassword;
        }

        int msglen = tEncryptionDescriptor.mPasswordLen;

        if (!plaintext) {
            printf("        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F   0123456789ABCDEF\n");
            printf("  .......................................................................ENCRYPTED\n");
        } else {
            printf("  .......................................................................DECRYPTED\n");
        }

        HexDumpByteBuffer(dump, msglen);
    }

    int ExtractCurrentFile(int opt_extract_without_path, int *popt_overwrite) {

        ZoSEncryptionDescriptor tEncryptionDescriptor = ZoSEncryptionDescriptor(mUf);
        printf("  * Extrafield / Computed Password Lenght : %d / %d\n", tEncryptionDescriptor.mRawDescriptorLen,
               tEncryptionDescriptor.mPasswordLen);
        printf("\n");
        DisplayCurrentFileEncryptionDescriptor(false, tEncryptionDescriptor);
        DisplayCurrentFileEncryptionDescriptor(true, tEncryptionDescriptor);
        printf("\n");

        /* Borrowed from miniunz by Gilles Vollant*/
        unz_file_info64 file_info = {0};
        FILE *fout = NULL;
        void *buf = NULL;
        uint16_t size_buf = 8192;
        int errclose = UNZ_OK;
        int skip = 0;
        char filename_inzip[256] = {0};
        char *filename_withoutpath = NULL;
        const char *write_filename = NULL;
        char *p = NULL;

        mLastUnzError =
            unzGetCurrentFileInfo64(mUf, &file_info, filename_inzip, sizeof(filename_inzip), NULL, 0, NULL, 0);
        if (mLastUnzError != UNZ_OK) {
            printf("error %d with zipfile in unzGetCurrentFileInfo\n", mLastUnzError);
            return mLastUnzError;
        }

        p = filename_withoutpath = filename_inzip;
        while (*p != 0) {
            if ((*p == '/') || (*p == '\\'))
                filename_withoutpath = p + 1;
            p++;
        }

        if (*filename_withoutpath == 0) {
            if (opt_extract_without_path == 0) {
                printf("creating directory: %s\n", filename_inzip);
                MKDIR(filename_inzip);
            }
            return mLastUnzError;
        }

        buf = (void *)malloc(size_buf);
        if (buf == NULL) {
            printf("Error allocating memory\n");
            return UNZ_INTERNALERROR;
        }

        mLastUnzError = unzOpenCurrentFilePassword(mUf, (const char *)tEncryptionDescriptor.mPlainTextPassword);
        if (mLastUnzError != UNZ_OK)
            printf("error %d with zipfile in unzOpenCurrentFilePassword\n", mLastUnzError);

        if (opt_extract_without_path)
            write_filename = filename_withoutpath;
        else
            write_filename = filename_inzip;

        if ((mLastUnzError == UNZ_OK) && (*popt_overwrite == 0) && (check_file_exists(write_filename))) {
            char rep = 0;
            do {
                char answer[128];
                printf("  The file %s exists. Overwrite ? [y]es, [n]o, [A]ll: ", write_filename);
                if (scanf("%1s", answer) != 1)
                    exit(EXIT_FAILURE);
                rep = answer[0];
                if ((rep >= 'a') && (rep <= 'z'))
                    rep -= 0x20;
            } while ((rep != 'Y') && (rep != 'N') && (rep != 'A'));

            if (rep == 'N')
                skip = 1;
            if (rep == 'A')
                *popt_overwrite = 1;
        }

        if ((skip == 0) && (mLastUnzError == UNZ_OK)) {
            fout = fopen64(write_filename, "wb");
            if ((fout == NULL) && (opt_extract_without_path == 0) && (filename_withoutpath != (char *)filename_inzip)) {
                char c = *(filename_withoutpath - 1);
                *(filename_withoutpath - 1) = 0;
                makedir(write_filename);
                *(filename_withoutpath - 1) = c;
                fout = fopen64(write_filename, "wb");
            }
            if (fout == NULL)
                printf("error opening %s\n", write_filename);
        }

        if (fout != NULL) {
            printf("  -> Extracting: [%s]\n", write_filename);

            do {
                mLastUnzError = unzReadCurrentFile(mUf, buf, size_buf);
                if (mLastUnzError < 0) {
                    printf("error %d with zipfile in unzReadCurrentFile\n", mLastUnzError);
                    break;
                }
                if (mLastUnzError == 0)
                    break;
                if (fwrite(buf, mLastUnzError, 1, fout) != 1) {
                    printf("error %d in writing extracted file\n", errno);
                    mLastUnzError = UNZ_ERRNO;
                    break;
                }
            } while (mLastUnzError > 0);

            if (fout)
                fclose(fout);

            if (mLastUnzError == 0)
                change_file_date(write_filename, file_info.dos_date);
        }

        errclose = unzCloseCurrentFile(mUf);
        if (errclose != UNZ_OK)
            printf("error %d with zipfile in unzCloseCurrentFile\n", errclose);

        free(buf);
        return mLastUnzError;
    }

    SsnZipFile(const char *filename) { ParsePEFile(filename); }
    // SsnZipFile(std::string filename) { ParsePEFile2(filename); }
};
