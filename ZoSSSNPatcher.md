# ZOS SSN Patcher files

Be them *.patchmanifest, *.version, *.solidpkg and so on, they are all

* A simple Windows PE file
* Signed (and checked for integrity) by Usually both SSN and ZoS
* Embedding a Zip File containing 1 encrypted file, being the payload

# PAYLOADS

## .patchmanifests 

* embeds "manifest.xml"
* are downloaded as instructed by the "applicationList", which comes from "applications.json" or "applications_mac.json" depending on OS (http://launcher.bethesda.net/applications[_mac].json).
* they contain all current and past specific URL to download assets and game files and runtimes
* they link to .solidpkg files
* the "-1toX" versions are those that contains no incremental subpart and are what the patcher target either when incremental patching is not possible or when the full file group is absent (i.e. no "depot" directory)

## .solidpkg

* are parsable binary format used initially for the P2P SSN system, that ZoS doest use anymore, as it uses only the "ReliableURLS", HTTP counterpart and immediately available.
* They describe each the number of zip disk for targetetted group of files
* substitution of the .solidpkg extension by '/assetname.[zip,z01,..]' lead to actual zip disks

## .zip and subdisks

* are not encrypted at all
* but are usually reversed or have the zip file central directory separated
* it is usually needed to either concatenate in reverse order the .zip and the firt subdisk to actually be able to unzip (e.g `cat depot_-1to159.z01 depot_-1to159.zip > depot_-1to159.zip-clean.zip`). others disks should remain untouched

## .version

* embed "version.xml"
* essentially just proper hashes of files so integrity is checked and from there are made decision on firing the Xdelta machinery of patcher.dll to either repair or upgrade

# Special case

* the most interesting and important case is the Launcher executabl itself, as it embeds its own zipfile with everything that is used by the launcher and the lib, all this under an old custom libCEF.
* EACH file in the zip has a different password, being unpredictable and not derived from filename or what, with up to 0x77 char lenght for the Password. 
* Crypto is legacy ZipCrypto

## Getting a zipfile

A simple Findpattern after reading it's own content stopping at first occurence of ZIPFile Local Header is sufficient for any payload

## Getting the password of each files

* For each files, in both local header and central directory, an extrafield 0001 with id 0x8810 is present.
* Lenght of the extrafield payload is actually lenght of password
* Payload is Xored original password. Decryption seems to rely more on some blackmagic "crypto" that I failed to get the point. It is NULL preserving and it has the pretention of always resulting in an ASCII password. Which it usually fails to, so the password has to be given programmatically.

The Decryption function :

```
	enum class Const {
		ShiftHiBound = 0x21,
		ShiftLoBound = 0x7e,
		PasswordLenHiBound = 0x77,
		ShifMaxIterations = 0x8,
	};

	uint16_t mRawDescriptorLen = (int)Const::PasswordLenHiBound;
	unsigned char mRawDescriptor[(int)Const::PasswordLenHiBound] = { 0 };
    uint16_t mPasswordLen = 0;
	unsigned char* mEncryptedPassword;
	unsigned char mPlainTextPassword[(int)Const::PasswordLenHiBound] = { 0 };

	static void UnXor(BYTE* pEncryptedPassword) {
		BYTE in, out;
		int ctr, shift;

		ctr = 0;
		in = *pEncryptedPassword;
		while ((in != '\0' && (ctr < (int)Const::PasswordLenHiBound))) {
			shift = (int)Const::ShifMaxIterations;
			out = ('\x01' << (ctr & 0x1f)) + pEncryptedPassword[ctr] ^ pEncryptedPassword[(int)Const::PasswordLenHiBound];
			while ((BYTE)Const::ShiftLoBound < out && (0 < shift)) {
				out = out & ~('\x01' << (shift & 0x1f));
				shift--;
			}
			if (out < (BYTE)Const::ShiftHiBound) {
                out = ('\x01' << (out % 3 + 5) | out) + 1;
			}
			pEncryptedPassword[ctr] = out;
			ctr++;
			in = pEncryptedPassword[ctr];
		}
		pEncryptedPassword[ctr] = '\0';
	}
```

## Demo Utility
* a macosx ready but easy to compile on VS too is provided (don't forget to rename lib/minizip/iowin32.* files back)
* The tool is able to parse any SSN PE File, finding the zip file, and extract one or all embedded file, along with verbose password and plaintext hex dumps.
* Note that regarding the Mac Launcher, the zipfile is not embeded in executable but lies as "app.bundle" in the .app/Contents/Resources directory. It still is signed and has to be parsed.

```
❯ ./E210Adm ~/Library/Application\ Support/Steam/steamapps/common/Zenimax\ Online/Launcher.app/Contents/Resources/app.bundle app.config.xml

  ███████╗██████╗  ██╗ ██████╗  █████╗ ██████╗ ███╗   ███╗
  ██╔════╝╚════██╗███║██╔═████╗██╔══██╗██╔══██╗████╗ ████║
  █████╗   █████╔╝╚██║██║██╔██║███████║██║  ██║██╔████╔██║
  ██╔══╝  ██╔═══╝  ██║████╔╝██║██╔══██║██║  ██║██║╚██╔╝██║
  ███████╗███████╗ ██║╚██████╔╝██║  ██║██████╔╝██║ ╚═╝ ██║
  ╚══════╝╚══════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝
  █████████████████████████████ The PatchManifest Unfailer

  -> /Users/colinj.brigato/Library/Application Support/Steam/steamapps/common/Zenimax Online/Launcher.app/Contents/Resources/app.bundle
  --> Found Embedded ZipFile start at 0x0450
!error 0 with zipfile in unzLocateFile
  * Extrafield / Computed Password Lenght : 40 / 36

  * Password decryption :
        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F   0123456789ABCDEF
  .......................................................................ENCRYPTED
  000: 6F 88 F6 89 3C 5A B5 DA 54 D3 A5 5C 68 26 66 86 | o...<Z..T..\h&f.
  010: 6F 1D CC 3D F5 1C B5 D2 83 AF B8 60 E4 77 79 AE | o..=.......`.wy.
  020: 17 7F A6 A3 .. .. .. .. .. .. .. .. .. .. .. .. | ....
  .......................................................................DECRYPTED
  000: 70 4B 7A 92 4C 7A 75 5A 54 53 25 5C 68 26 66 27 | pKz.LzuZTS%\h&f'
  010: 6F 9E 4C 3D 75 5D 35 52 24 2F 38 60 64 77 79 2E | o.L=u]5R$/8`dwy.
  020: 39 42 2A 2B .. .. .. .. .. .. .. .. .. .. .. .. | 9B*+

  -> Extracting: [app.config.xml]

~/E210Adm/E210Adm
❯ head -n3 app.config.xml
<?xml version="1.0" encoding="utf-8" ?>
<AppConfig>
    <Macros>
```

## Modifying Launcher behavior

* Launcher behavior is very easy to follow if one start by looking at app.config.xml (then main config, workflow, appliation handling, etc) and is easy to reproduce.
* But Launcher as some embedded secrets still lying in the executable which are willingly not disclosed here.
* Yet, one can still modify the launcher behavior and, for example, the branch and type (partner, internal etc) of the patcher by modifying embbeded zip file or app bundle providing the 0x8810 extra field is properly reconstructed.
* To bypass initial Integrity/Signature security, just add the /DisableSecurity parameter to the launcher, it works on any versions.
* handling applications.json and parts of remote payloads leads to interesting knowledge too.

## Example complete workflow : retrieving last client Executables (without depot/vo_*)

1. Get `app.config.xml` from embedded Launcher executable

```
./E210Adm ~/Library/Application\ Support/Steam/steamapps/common/Zenimax\ Online/Launcher/Bethesda.net_Launcher.exe app.config.xml
...
-> Extracting: [app.config.xml]
```

2. Check config for next step, iterate until you get to applications list remote file:
```
cat app.config.xml | xpup '/*/StartupWindowConfig'
main.config.xml
...

./E210Adm ~/Library/Application\ Support/Steam/steamapps/common/Zenimax\ Online/Launcher/Bethesda.net_Launcher.exe main.config.xml
...
-> Extracting: [main.config.xml]

cat main.config.xml | xpup '/*/Skin/WorkflowPath'
workflow.json

./E210Adm ~/Library/Application\ Support/Steam/steamapps/common/Zenimax\ Online/Launcher/Bethesda.net_Launcher.exe workflow.json
...
-> Extracting: [workflow.json]

cat workflow.json|jq -r '.loadApps.config.updateUrl'
http://launcher.bethesda.net/applications.json
```

3. Get applications list, choose the `game_player` patchmanifest (client files) of either version (PTS, Live, ...) alongside with Macros and variables, then deduce patchmanifest URL:

```
 curl -s "http://launcher.bethesda.net/applications.json" | jq -r '.applications[0].properties.macros,.templates.ZOSEnvTemplate.isPatchable2.url'
{
  "TemplateEnvironment": "The Elder Scrolls Online",
  "TemplateEnvIDdepot": "ESO",
  "TemplateEnvIDgame": "ESO",
  "TemplateEnvIDvo": "ESO",
  "TemplateEnvIDvosoundset": "ESO",
  "TemplateGametype": "{GamePayloadPublic}",
  "TemplateGameFolder": "{GameFolder}",
  "TemplateManifestURL": "launcher.bethesda.net",
  "TemplateGameExe": "{GameExe}"
}
http://{TemplateManifestURL}/{TemplateEnvIDgame}/{TemplateGametype}.patchmanifest
...

wget http://launcher.bethesda.net/ESO/game_player.patchmanifest
...
2020-09-16 14:53:42 (919 KB/s) — « game_player.patchmanifest » sauvegardé [34808/34808]
```

4. Extract "manifest.xml" and parse it for last available "-1toX" package :

```
./E210Adm game_player.patchmanifest
...
-> Extracting: [manifest.xml]

❯ cat manifest.xml |grep http|grep "\-1to"|tail -n1|xpup 'Value'
http://live.patcher.elderscrollsonline.com/products/eso/874DCDCF-C40C-4956-92FE-E39B8DC4764E/game_player/game_player_-1to378.solidpkg
```

5. Either read/parse the solidpkg or jump to downloading assets (game_player has one disk only + central directory appart, so .zip and .z01 are only existing and needed files) ; then recompose usable zip file without side central directory aberration :

```
wget http://live.patcher.elderscrollsonline.com/products/eso/874DCDCF-C40C-4956-92FE-E39B8DC4764E/game_player/game_player_-1to378/game_player_-1to378.zip

wget http://live.patcher.elderscrollsonline.com/products/eso/874DCDCF-C40C-4956-92FE-E39B8DC4764E/game_player/game_player_-1to378/game_player_-1to378.z01

cat game_player_-1to378.z01 game_player_-1to378.zip > game_player_-1to378-clean.zip

...
-rw-r--r--  1 colinj.brigato  wheel   101M 16 sep 15:02 game_player_-1to378-clean.zip libzip usable result
-rw-r--r--  1 colinj.brigato  wheel   101M  4 sep 12:42 game_player_-1to378.z01  (local headers and files)
-rw-r--r--  1 colinj.brigato  wheel    12K  4 sep 12:42 game_player_-1to378.zip  (central directory)

```

6. Unzip, not worrying of central directory eventual failure, it should work with fallbackk from localheaders anyway (depends on your zip implementation)

```
 unzip game_player_-1to378-clean.zip
Archive:  game_player_-1to378-clean.zip
warning [game_player_-1to378-clean.zip]:  zipfile claims to be last disk of a multi-part archive;
  attempting to process anyway, assuming all parts have been concatenated
  together in order.  Expect "errors" and warnings...true multi-part support
  doesn't exist yet (coming soon).
error [game_player_-1to378-clean.zip]:  NULL central directory offset
  (attempting to process anyway)
  inflating: client/AppSettings.txt
  inflating: client/bink2w64.dll
  inflating: client/cacert.pem
  inflating: client/ChromaAppInfo.xml
  inflating: client/crash-reporter-en.ini
  inflating: client/d3dcompiler_47.dll
  inflating: client/dbghelp.dll
  inflating: client/ErrorStrings.txt
  inflating: client/eso.manifest
  inflating: client/eso64.exe
  inflating: client/ESORequirementChecker.exe
  inflating: client/EsoThirdParty.rtf
  inflating: client/game.mnf
  inflating: client/game0000.dat
  inflating: client/granny2_x64.dll
  inflating: client/icudt55_x64.dll
  inflating: client/icuin55_x64.dll
  inflating: client/icuuc55_x64.dll
  inflating: client/msvcr100.dll
  inflating: client/Platforms.xml
  inflating: client/rad_tm_win64.dll
  inflating: client/steam_api64.dll
  inflating: client/ZoCrashReporter.exe
  inflating: game_player.version

```

7. Tada !

```
ls -ahl client/
total 320424
drwxr-xr-x  25 colinj.brigato  wheel   800B 16 sep 15:04 ./
drwxr-xr-x   7 colinj.brigato  wheel   224B 16 sep 15:04 ../
-rw-r--r--   1 colinj.brigato  wheel    67B  4 sep 00:17 AppSettings.txt
-rw-r--r--   1 colinj.brigato  wheel   614B  4 sep 01:20 ChromaAppInfo.xml
-rw-r--r--   1 colinj.brigato  wheel   248K  4 sep 01:20 ESORequirementChecker.exe
-rw-r--r--   1 colinj.brigato  wheel   3,7K  4 sep 01:20 ErrorStrings.txt
-rw-r--r--   1 colinj.brigato  wheel   130K  4 sep 01:20 EsoThirdParty.rtf
-rw-r--r--   1 colinj.brigato  wheel   719B  4 sep 00:17 Platforms.xml
-rw-r--r--   1 colinj.brigato  wheel   437K  4 sep 01:20 ZoCrashReporter.exe
-rw-r--r--   1 colinj.brigato  wheel   366K  4 sep 01:20 bink2w64.dll
-rw-r--r--   1 colinj.brigato  wheel   220K  4 sep 01:20 cacert.pem
-rw-r--r--   1 colinj.brigato  wheel   453B  4 sep 00:17 crash-reporter-en.ini
-rw-r--r--   1 colinj.brigato  wheel   4,0M  4 sep 01:20 d3dcompiler_47.dll
-rw-r--r--   1 colinj.brigato  wheel   963K  4 sep 01:20 dbghelp.dll
-rw-r--r--   1 colinj.brigato  wheel   942B  4 sep 01:20 eso.manifest
-rw-r--r--   1 colinj.brigato  wheel    39M  4 sep 01:20 eso64.exe
-rw-r--r--   1 colinj.brigato  wheel   127K  4 sep 00:56 game.mnf
-rw-r--r--   1 colinj.brigato  wheel    82M  4 sep 00:56 game0000.dat
-rw-r--r--   1 colinj.brigato  wheel   671K  4 sep 01:20 granny2_x64.dll
-rw-r--r--   1 colinj.brigato  wheel    25M  4 sep 01:20 icudt55_x64.dll
-rw-r--r--   1 colinj.brigato  wheel   1,9M  4 sep 01:20 icuin55_x64.dll
-rw-r--r--   1 colinj.brigato  wheel   1,3M  4 sep 01:20 icuuc55_x64.dll
-rw-r--r--   1 colinj.brigato  wheel   756K  4 sep 01:20 msvcr100.dll
-rw-r--r--   1 colinj.brigato  wheel   172K  4 sep 01:20 rad_tm_win64.dll
-rw-r--r--   1 colinj.brigato  wheel   230K  4 sep 01:20 steam_api64.dll
```

8. (Optional) You can check integrity yourself by decrypting "version.xml" from downloaded game_player.version
```
./E210Adm /tmp/game_player/game_player.version
-> Extracting: [version.xml]

cat version.xml | xpup '/*/*/File[10]'

      client/eso64.exe
      Fri, 04 Sep 2020 01:20:04 GMT
      40441856
      84a73e197c9aacda64643fe9118b3e36a3ea3ad0
      
❯ ls -ahl /tmp/game_player/client/eso64.exe
-rw-r--r--  1 colinj.brigato  wheel    39M  4 sep 01:20 /tmp/game_player/client/eso64.exe

❯ sha1sum /tmp/game_player/client/eso64.exe
84a73e197c9aacda64643fe9118b3e36a3ea3ad0  /Tmp/game_player/client/eso64.exe
```

# Happy hacking !
