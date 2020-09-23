#include <fstream>
#include <vector>
//#include <windows.h>
//#include <direct.h>
#include <iostream>

#include <sstream>
#include <string>

#include "../lib/minizip/ioapi_mem.h"
#include "../lib/minizip/minishared.h"
#include "../lib/minizip/unzip.h"
#include "ANSI.h"
#include "SsnZipFile.h"
#include "ZoSEncryptionDescriptor.h"
#include <unistd.h>

#ifdef E210ADM_STATIC_ZOS_SSN_ZIPCRYPTO_LUT
#include "STATIC_ZOS_SSN_ZIPCRYPTO_LUT.h"
#endif

namespace E210Adm {

unsigned char kZosEncryptorLookkupTable[8][256];

void Banner() {
    printf("\n");
    printf("  ███████╗██████╗  ██╗ ██████╗  █████╗ ██████╗ ███╗   ███╗\n");
    printf("  ██╔════╝╚════██╗███║██╔═████╗██╔══██╗██╔══██╗████╗ ████║\n");
    printf("  █████╗   █████╔╝╚██║██║██╔██║███████║██║  ██║██╔████╔██║\n");
    printf("  ██╔══╝  ██╔═══╝  ██║████╔╝██║██╔══██║██║  ██║██║╚██╔╝██║\n");
    printf("  ███████╗███████╗ ██║╚██████╔╝██║  ██║██████╔╝██║ ╚═╝ ██║by Colin J.Brigato \n");
    printf("  ╚══════╝╚══════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝     (c) 2020\n");
    printf("  █████████████████████████████ The PatchManifest Unfailer\n");
    printf("\n");
}

void Help() {
    printf(
        "Usage : Error210Adm [-t 0feb5c..] | [-c 0-ff] | [-e] [-x] [-l] [-o] file.<patchmanifest|version|solidpkg|...> "
        "[file_to_extr.] [-d "
        "extractdir]\n\n"
        "  -e  Extract without path (junk paths)\n"
        "  -x  Extract with path (default)\n"
        "  -l  only list files\n"
        "  -d  directory to extract into (default is current directory)\n"
        "  -o  overwrite files without prompting\n"
        "  -t  hex string of encrypted password to dump plaintext\n"
        "  -c  print dynamic verbose ZoSEncryptionDescriptor Lookup Tables\n"
        "  -g  generate and print static ZosEncryptionDescriptor LUT header file\n"
        "  -R  reverse ZosEncryption (hex string of decrypted bytes->compute encrypted candidates (LUT))\n"
        "  -r  as -R but ASCII string input\n\n");
}

void AutoSSNPeFile(SsnExtractConf config) {

    SsnZipFile szf = SsnZipFile(config.zipfilename);

    if (config.opt_do_list) {
        szf.ListFilesInZip();
        return;
    }
    if (config.opt_extractdir && chdir(config.dirname)) {
        printf("Error changing into %s, aborting (Does output directory exists ?)\n", config.dirname);
        exit(-1);
    }
    if (config.filename_to_extract) {
        szf.LocateFile(config.filename_to_extract);
        szf.ExtractCurrentFile(config.opt_do_extract_withoutpath, &config.opt_overwrite);
        return;
    } else {
        szf.ExtractAllFiles(config.opt_do_extract_withoutpath, &config.opt_overwrite);
    }
    return;
}

void ComputeZosEncryptionLookupTable() {
    static bool once = false;
    if (once)
        return;
    for (int k = 0; k < 8; k++) {
        unsigned char byte[256] = {1};
        memset(byte, 1, 256);
        for (int j = 0; j < 256; j++) {
            byte[k] = j;
            byte[k + 1] = 0;
            ZoSEncryptionDescriptor::ZoSMungeToAscii(byte);
            kZosEncryptorLookkupTable[k][j] = byte[k];
        }
    }
    once = true;
}

std::vector<unsigned char> FindEncryptedCandidates(unsigned char DEC_BYTE, uint8_t POS) {
    ComputeZosEncryptionLookupTable();
    POS &= 0x1f;
    if (POS > 7)
        POS = 7;
    std::vector<unsigned char> candidates;
    for (int i = 0; i < 256; i++) {
        if (kZosEncryptorLookkupTable[POS][i] == DEC_BYTE) {
            candidates.push_back(i);
        }
    }
    return candidates;
}

void DecryptZosEncryptionString(const char *zos_encrypted_string) {
    std::string hex_chars(zos_encrypted_string);
    std::istringstream hex_chars_stream(hex_chars);
    std::vector<unsigned char> enc_bytes;
    unsigned int c;
    while (hex_chars_stream >> std::hex >> c) {
        enc_bytes.push_back(c);
    }
    ZoSEncryptionDescriptor tEncryptionDescriptor = ZoSEncryptionDescriptor(&enc_bytes[0], enc_bytes.size());
    printf("\n");
    SsnZipFile::DisplayCurrentFileEncryptionDescriptor(false, tEncryptionDescriptor);
    SsnZipFile::DisplayCurrentFileEncryptionDescriptor(true, tEncryptionDescriptor);

#ifdef E210ADM_STATIC_ZOS_SSN_ZIPCRYPTO_LUT
    printf("  .......................................................................DECRYPTED[LUT]\n");
    std::vector<unsigned char> dec_bytes;
    for (int v = 0; v < enc_bytes.size(); v++) {
        dec_bytes.push_back(lookup_ZOS_SSN_ZIPCRYPTO_LUT(enc_bytes[v], v));
    }
    SsnZipFile::HexDumpByteBuffer(&dec_bytes[0], dec_bytes.size());
    printf("\n");
#endif
}

void EncryptZosEncryptionString(const char *zos_decrypted_string, bool as_hex_string) {
    std::vector<unsigned char> dec_bytes;
    if (!as_hex_string) {
        int len = strnlen(zos_decrypted_string, 0x77);
        for (int i = 0; i < len; i++) {
            dec_bytes.push_back(zos_decrypted_string[i]);
        }
    } else {
        std::string hex_chars(zos_decrypted_string);
        std::istringstream hex_chars_stream(hex_chars);

        unsigned int c;
        while (hex_chars_stream >> std::hex >> c) {
            dec_bytes.push_back(c);
        }
    }

    std::vector<std::vector<unsigned char>> enc_bytes_str_candidates;
    for (int i = 0; i < dec_bytes.size(); i++) {
        // std::vector<unsigned char> enc_bytes_char_candidate;
        enc_bytes_str_candidates.push_back(FindEncryptedCandidates(dec_bytes[i], i));
    }
    for (int i = 0; i < dec_bytes.size(); i++) {
        printf("* Encrypted Candidates for %02X byte with pos %02X : ", dec_bytes[i], i);
        for (int j = 0; j < enc_bytes_str_candidates[i].size(); j++) {
            printf("%02x, ", enc_bytes_str_candidates[i][j]);
        }
        printf("\n");
    }
}

void GenerateAndPrintZosEncryptionStaticLUT() {
    printf("// This file was generated by `E210Adm -g`\n");
    printf("// DO NOT EDIT THIS FILE \n\n");

    printf("#ifndef _STATIC_ZOS_SSN_ZIPCRYPTO_LUT_H_\n");
    printf("#define _STATIC_ZOS_SSN_ZIPCRYPTO_LUT_H_\n\n");

    printf("static const unsigned char ZOS_SSN_ZIPCRYTO_LUT[8][256] = {\n");
    for (int zsl = 0; zsl < 256; zsl++) {
        printf("{");
        for (int zsm = 0; zsm < 8; zsm++) {
            char eor[3] = ", ";
            if (zsm == 7)
                eor[0] = '\0';
            printf("0x%02x%s", kZosEncryptorLookkupTable[zsm][zsl], eor);
        }
        printf("},\n");
    }
    printf("};\n\n");
    printf("unsigned char lookup_ZOS_SSN_ZIPCRYPTO_LUT(unsigned char ENC_BYTE, uint8_t POS)\n");
    printf("{\n");
    printf("    POS &= 0x1F;\n");
    printf("    if (POS>=7) {\n");
    printf("        POS=7;\n");
    printf("    }\n");
    printf("    return ZOS_SSN_ZIPCRYTO_LUT[ENC_BYTE][POS];\n");
    printf("}\n\n");
    printf("#endif\n");
}

void PrettyPrintZosEncryptionLookupTable() {
    printf("        [f(ENC_BYTE,mod32(POSITION)) = DEC_BYTE]\n\n");
    printf("        |        POSITION %% 32                  \n");
    printf("--------+---------------------------+------------\n");
    printf("ENC_BYTE|         DEC_BYTES         |  ISPRINT()\n");
    printf("--------+---------------------------+------------\n");
    printf("        |" BYEL " 00 01 02 03 04 05 06 >7.." reset " |" BYEL " 0123456 >=7" reset "\n");
    printf("        | -- -- -- -- -- -- -- ---- | ------- ---\n");
    for (int l = 0; l < 256; l++) {
        if (l == 0x20 || l == 0x7f) {
            printf("--------+----------------------------+-------------\n");
        }

        if (isprint(l)) {
            printf(" (%c)", l);
        } else {
            printf("    ");
        }

        printf(" %02x | ", l);
        for (int m = 0; m < 8; m++) {
            printf(GRN);
            if (!isprint(kZosEncryptorLookkupTable[m][l]))
                printf(RED);
            if (m == 7) {

                printf(" %02x" reset " ", kZosEncryptorLookkupTable[m][l]);
            } else {
                printf("%02x " reset, kZosEncryptorLookkupTable[m][l]);
            }
        }

        printf(" | ");
        for (int n = 0; n < 8; n++) {
            if (n == 7)
                printf("  ");
            if (isprint(kZosEncryptorLookkupTable[n][l])) {
                printf(GRN "%c", kZosEncryptorLookkupTable[n][l]);
            } else {
                printf(RED "─");
            }
            if (n == 7) {
                printf(reset " ");
            }
        }

        printf("\n");
    }
}
} // namespace E210Adm

int main(int argc, char **argv) {
    const char *zipfilename = NULL;
    const char *filename_to_extract = NULL;
    int i = 0;
    int opt_do_list = 0;
    int opt_do_extract = 1;
    int opt_do_extract_withoutpath = 0;
    int opt_overwrite = 0;
    int opt_extractdir = 0;
    const char *dirname = NULL;
    const char *zos_encrypted_string = NULL;
    const char *zos_decrypted_string = NULL;
    bool as_hex_string = false;

#ifndef E210ADM_STATIC_ZOS_SSN_ZIPCRYPTO_LUT
    E210Adm::ComputeZosEncryptionLookupTable();
#endif

    if (argc == 1) {
        E210Adm::Banner();
        E210Adm::Help();
        return 0;
    }

    /* Parse command line options */
    for (i = 1; i < argc; i++) {
        if ((*argv[i]) == '-') {
            const char *p = argv[i] + 1;

            while (*p != 0) {
                char c = *(p++);
                if ((c == 't') || (c == 'T')) {
                    E210Adm::Banner();
                    zos_encrypted_string = argv[i + 1];
                    E210Adm::DecryptZosEncryptionString(zos_encrypted_string);
                    return 0;
                }
                if ((c == 'r') || (c == 'R')) {
                    E210Adm::Banner();
                    zos_decrypted_string = argv[i + 1];
                    if (c == 'R')
                        as_hex_string = true;
                    E210Adm::EncryptZosEncryptionString(zos_decrypted_string, as_hex_string);
                    return 0;
                }
                if ((c == 'g') || (c == 'G')) {
                    E210Adm::ComputeZosEncryptionLookupTable();
                    E210Adm::GenerateAndPrintZosEncryptionStaticLUT();
                    return 0;
                }
                if ((c == 'c') || (c == 'C')) {
                    E210Adm::Banner();
                    E210Adm::ComputeZosEncryptionLookupTable();
                    E210Adm::PrettyPrintZosEncryptionLookupTable();
                    return 0;
                }
                if ((c == 'l') || (c == 'L'))
                    opt_do_list = 1;
                if ((c == 'x') || (c == 'X'))
                    opt_do_extract = 1;
                if ((c == 'e') || (c == 'E'))
                    opt_do_extract = opt_do_extract_withoutpath = 1;
                if ((c == 'o') || (c == 'O'))
                    opt_overwrite = 1;
                if ((c == 'd') || (c == 'D')) {
                    opt_extractdir = 1;
                    dirname = argv[i + 1];
                }
            }
        } else {
            if (zipfilename == NULL)
                zipfilename = argv[i];
            else if ((filename_to_extract == NULL) && (!opt_extractdir))
                filename_to_extract = argv[i];
        }
    }

  E210Adm::Banner();
  SsnExtractConf config = SsnExtractConf{zipfilename, filename_to_extract, opt_do_list, opt_do_extract, opt_do_extract_withoutpath, opt_overwrite, opt_extractdir, dirname};
  E210Adm::AutoSSNPeFile(config);

  return 0;
}
