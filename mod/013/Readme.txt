This modification does not use OpenSSL.
Word list BIP-39 is connected. Added inclusion of the BrainWallet algorithm. 
Number of words 1-16. Seed can be in HEX format with a length of 128 bits. 
You can set an arbitrary seed with the -s option. 
Repeat the seed from the one saved earlier in the Result.txt file.
Launch options Puzzle 32 BTC:
VanitySearch.exe -stop -t 1 -bits 66 -r 1 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 
Launch options help:
VanitySearch.exe -h
VanitySearch.exe -check
Launch options check:
VanitySearch.exe -stop -t 1 -brainwallet 3 -s "bla bla bla" 165i1knU3ang5mEBHikiz8PmXF5svyU5pg 
VanitySearch.exe -stop -t 1 -r 10 -brainwallet 3 -s "bla bla bla" -u 177HfVC1dWE9wXaT4kC4g4zFBCystRa9ki 
VanitySearch.exe -stop -bip39 12 -t 1 -bits 28 -r 1 12jbtzBb54r97TCwW3G1gCFoumpckRAPdY 
--//--
Modify 010 

Fixed Seed to lowercase!

PBKDF2-HMAC-SHA512 2048 Rounds of Seed for Expansion to 512 bits. Enable Function Option: -level 1

Output file name added bits and time.

Verbose level info. Option: -verbose 1 or -verbose 2

Flags were placed and other adjustments were made.

--//--
Modify 011 

Added functions:

- BIP32 Derivation Path m/0

- Normal Child extended private key

- Serialization Extended Private Key 

Vector Test is successful.
SECP256K1.cpp - Output data keys string switch to lowercase.
Enable OpenSSL - Generate Random Seed.
Option: -verbose 4 Enable all info.
Option: -verbose 0 Disable all info.
Rekey multiply by 1000.

--//--
Modify 012
..........

--//--
Modify 013

Added Path - m/0'/0'/66' For 32 BTC Puzzle / Check keys online - https://iancoleman.io/bip39/ 

Use SSE2 instructions - default VanitySearch code / Disable SSE cmd: -nosse 

Initial SEED extension to 64 bits

GPU Added rotation - #define NB_SPIN 16

Modification file GPUHash.h

The speed on the Tesla T4 GPU is 670.98 Mkeys/s

If Use GPU Rekey multiple by 1000

RUN CMD:

VanitySearch.exe -stop -nosse -verbose 1 -level 0 -t 1 -bits 66 -r 10 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so

VanitySearch.exe -stop -t 0 -nosse -o Result.txt -verbose 1 -level 0 -gpu -r 500000000 -bits 66 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 

Added play sound buzzer.wav in Windows version ;)



..........
The code can be rewritten ;-)



