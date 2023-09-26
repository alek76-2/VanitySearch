# VanitySearch
Forked from https://github.com/JeanLucPons/VanitySearch 

This experimental project. Increased speed, removed unnecessary functions.

# Usage for 32 BTC Puzzle 

Run programm used GPU

./VanitySearch -stop -t 0 -gpu -bits 66 -r 50000 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

./VanitySearch -stop -t 0 -gpu -bits 66 -r 50000 -level 2 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

./VanitySearch -stop -t 0 -gpu -bits 66 -r 50000 -level 3 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

./VanitySearch -stop -t 0 -gpu -bits 66 -r 50000 -level 4 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

./VanitySearch -stop -t 0 -bits 66 -start 0000000000000000000000000000000000000000000000020000000000000000 -gpu 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

Run programm used CPU

./VanitySearch -stop -t 1 -bits 66 -r 50 -level 1 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

./VanitySearch -stop -t 2 -bits 66 -r 50 -level 4 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

----------------------------------------------------------------------------------------------------------------
Check Bits: 28 \
Compressed Address: \
12jbtzBb54r97TCwW3G1gCFoumpckRAPdY \
Address hash160: \
1306b9e4ff56513a476841bac7ba48d69516b1da \
Secret wif: 2SaK6n3GY7WKrHRSyvhrn1k6zdzeAMmNBXH5PtXqoEYscExVUKsh2G \
Secret hex: \
0xd916ce8 \
pk: \
03e9e661838a96a65331637e2a3e948dc0756e5009e7cb5c36664d9b72dd18c0a7 

./VanitySearch -stop -t 2 -bits 28 -r 5 12jbtzBb54r97TCwW3G1gCFoumpckRAPdY 

./VanitySearch -stop -t 0 -gpu -bits 28 -r 50000 12jbtzBb54r97TCwW3G1gCFoumpckRAPdY 

----------------------------------------------------------------------------------------------------------------

# Compilation

## Windows

Intall CUDA SDK and build OpenSSL, open VanitySearch.sln in Visual C++ 2017. \
You may need to reset your *Windows SDK version* in project properties. \
In Build->Configuration Manager, select the *Release* configuration. \
Build OpenSSL: \
Install Netwide Assembler (NASM).  \
Download NASM x64 https://www.nasm.us/pub/nasm/releasebuilds/2.16.01/win64/nasm-2.16.01-installer-x64.exe \
Add Path C:\Program Files\NASM\; \
Add PATHEXT .PL; before .BAT; \
those. - .COM;.EXE;.PL;.BAT; \
And be sure to restart your PC. \
Download the library from the official website openssl-1.0.1a.tar.gz \
http://www.openssl.org/source/old/1.0.1/openssl-1.0.1a.tar.gz \
Unpack openssl-1.0.1a.tar.gz into the openssl-1.0.1a directory and copy its contents to the directory: \
c:\openssl-src-64 \
Run Command Prompt Visual Studio - x64 Native Tools Command Prompt for VS 2017 as administrator \
Run commands: \
cd C:\openssl-src-64 \
perl Configure VC-WIN64A --prefix=C:\Build-OpenSSL-VC-64 \
ms\do_win64a \
nmake -f ms\ntdll.mak \
nmake -f ms\ntdll.mak install \
nmake -f ms\ntdll.mak test 

Build OpenSSL complete. \
Connecting libraries to a project in Visual Studio 2017 Community. \
It's very simple! \
Go to Solution Explorer - Project Properties and select: 
1. Select C/C++ next: \
C/C++ - General - Additional directories for included files - Edit - Create a line and specify the path: \
C:\Build-OpenSSL-VC-64\include \
OK 
2. Select Linker next: \
Linker - Input - Additional dependencies - Edit and specify the path: \
c:\Build-OpenSSL-VC-64\lib\ssleay32.lib \
c:\Build-OpenSSL-VC-64\lib\libeay32.lib \
OK \
Project Properties - Apply - OK \
Build and enjoy.\
\
Note: The current relase has been compiled with CUDA SDK 10.2, if you have a different release of the CUDA SDK, you may need to update CUDA SDK paths in VanitySearch.vcxproj using a text editor. 
The current nvcc option are set up to architecture starting at 3.0 capability, for older hardware, add the desired compute capabilities to the list in GPUEngine.cu properties, CUDA C/C++, Device, Code Generation.

## Linux

Intall OpenSSL.\
Intall CUDA SDK.\
Depenging on the CUDA SDK version and on your Linux distribution you may need to install an older g++ (just for the CUDA SDK).\
Edit the makefile and set up the good CUDA SDK path and appropriate compiler for nvcc. 

```
CUDA       = /usr/local/cuda-8.0
CXXCUDA    = /usr/bin/g++-4.8
```

You can enter a list of architectrure (refer to nvcc documentation) if you have several GPU with different architecture. Compute capability 2.0 (Fermi) is deprecated for recent CUDA SDK.
VanitySearch need to be compiled and linked with a recent gcc (>=7). The current release has been compiled with gcc 7.3.0.\
Go to the VanitySearch directory. 
ccap is the desired compute capability https://ru.wikipedia.org/wiki/CUDA

```
$ g++ -v
gcc version 7.3.0 (Ubuntu 7.3.0-27ubuntu1~18.04)
$ make all (for build without CUDA support)
or
$ make gpu=1 ccap=20 all
```

# License

VanitySearch is licensed under GPLv3.
