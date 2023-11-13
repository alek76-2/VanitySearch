/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef VANITYH
#define VANITYH

#include <string>
#include <vector>
#include "SECP256k1.h"
#include "GPU/GPUEngine.h"
#ifdef WIN64
#include <Windows.h>
#endif

#define CPU_GRP_SIZE 1024

#define hmac_sha512_nb_round 2048

#define TARGET_KEY_BITS 66

#define TARGET_KEY_HIGH_BYTE 0x3 // 0x2 // 32 BTC Puzzle

#define BIP39_MAX_WORD 16 // max 16 !!!

class VanitySearch;

typedef struct {

  VanitySearch *obj;
  int  threadId;
  bool isRunning;
  bool hasStarted;
  bool rekeyRequest;
  int  gridSizeX;
  int  gridSizeY;
  int  gpuId;

} TH_PARAM;


typedef struct {

  char *prefix;
  int prefixLength;
  prefix_t sPrefix;
  double difficulty;
  bool *found;

  // For dreamer ;)
  bool isFull;
  prefixl_t lPrefix;
  uint8_t hash160[20];

} PREFIX_ITEM;

typedef struct {

  std::vector<PREFIX_ITEM> *items;
  bool found;

} PREFIX_TABLE_ITEM;

class VanitySearch {

public:

  VanitySearch(Secp256K1 *secp, std::vector<std::string> &prefix, std::string seed, std::string start_key, int Random_bit, int FuncLevel, int searchMode,
               bool useGpu, bool stop, bool bip39, bool brainwallet, int nb_Word, int flag_verbose, std::string outputFile, bool useSSE,uint32_t maxFound,uint64_t rekey,
               bool caseSensitive, Point &startPubKey, bool paranoiacSeed);

  void Search(int nbThread,std::vector<int> gpuId,std::vector<int> gridSize);
  void FindKeyCPU(TH_PARAM *p);
  void FindKeyGPU(TH_PARAM *p);

private:

  std::string GetHex(std::vector<unsigned char> &buffer);
  std::string GetExpectedTime(double keyRate, double keyCount);
  bool checkPrivKey(std::string addr, Int &key, int32_t incr, int endomorphism, bool mode);
  void checkAddr(int prefIdx, uint8_t *hash160, Int &key, int32_t incr, int endomorphism, bool mode);
  //void checkAddrSSE(uint8_t *h1, uint8_t *h2, uint8_t *h3, uint8_t *h4,
  //                  int32_t incr1, int32_t incr2, int32_t incr3, int32_t incr4,
  //                  Int &key, int endomorphism, bool mode);
  void checkAddresses(bool compressed, Int key, int i, Point p1);
  //void checkAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4);
  void output(std::string addr, std::string pAddr, std::string pAddrHex);
  bool isAlive(TH_PARAM *p);
  bool isSingularPrefix(std::string pref);
  bool hasStarted(TH_PARAM *p);
  void rekeyRequest(TH_PARAM *p);
  uint64_t getGPUCount();
  uint64_t getCPUCount();
  bool initPrefix(std::string &prefix, PREFIX_ITEM *it);
  void dumpPrefixes();
  double getDiffuclty();
  void updateFound();
  void getCPUStartingKey(int thId, Int& key, Point& startP);
  void getGPUStartingKeys(int thId, int groupSize, int nbThread, Int *keys, Point *p);
  void enumCaseUnsentivePrefix(std::string s, std::vector<std::string> &list);
  bool prefixMatch(char *prefix, char *addr);
  //
  void setSeed(int thId, bool fl);
  unsigned long ts_output;// Unix Timestamp
  void GetSeedBIP39(int thId, bool fl, std::string &s_seed, bool word_flag);
  void getKeysFromRandomSeedPRNG(int thId, int nbitU, bool word_fl, bool master, int nbThread, Int *keys);
  bool USE_WORD_LIST;
  bool Brainwallet_fl;
  int nb_word;
  int verbose_fl;
  void drvKey(std::string InData, std::string InKey, std::string &outMaster, std::string &outChain, uint64_t nb_iter, std::string &extended_key, Int &outIL, Int &outIR);
  //

  Secp256K1 *secp;
  Int startKey;
  Int key1;
  Int key2;
  Int key3;
  // Randon bits 
  int Random_bits;
  int FunctionLevel;
  bool keys_seed_fl;
  std::string Seed;
  std::string seed_output;
  //
  Point startPubKey;
  bool startPubKeySpecified;
  uint64_t counters[256];
  double startTime;
  int searchType;
  int searchMode;
  bool hasPattern;
  bool caseSensitive;
  bool useGpu;
  bool stopWhenFound;
  bool endOfSearch;
  int nbCPUThread;
  int nbGPUThread;
  int nbFoundKey;
  uint64_t rekey;
  uint64_t lastRekey;
  uint32_t nbPrefix;
  std::string outputFile;
  bool useSSE;
  bool onlyFull;
  uint32_t maxFound;
  double _difficulty;
  bool *patternFound;
  std::vector<PREFIX_TABLE_ITEM> prefixes;
  std::vector<prefix_t> usedPrefix;
  std::vector<LPREFIX> usedPrefixL;
  std::vector<std::string> &inputPrefixes;

  Int beta;
  Int lambda;
  Int beta2;
  Int lambda2;

#ifdef WIN64
  HANDLE ghMutex;
#else
  pthread_mutex_t  ghMutex;
#endif

};

#endif // VANITYH
