#include <cstring>
#include "nRF_AES.h"
#include "nRF_Random.h"
#include "nRF_Hash.h"

nRFCrypto_AES aes;
nRFCrypto_Random rnd;
nRFCrypto_Hash myHash;

void hexDump(unsigned char *buf, uint16_t len) {
  char alphabet[17] = "0123456789abcdef";
  Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
  Serial.print(F("   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |\n"));
  for (uint16_t i = 0; i < len; i += 16) {
    if (i % 128 == 0)
      Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
    char s[] = "|                                                | |                |\n";
    uint8_t ix = 1, iy = 52;
    for (uint8_t j = 0; j < 16; j++) {
      if (i + j < len) {
        uint8_t c = buf[i + j];
        s[ix++] = alphabet[(c >> 4) & 0x0F];
        s[ix++] = alphabet[c & 0x0F];
        ix++;
        if (c > 31 && c < 128) s[iy++] = c;
        else s[iy++] = '.';
      }
    }
    uint8_t index = i / 16;
    if (i < 256) Serial.write(' ');
    Serial.print(index, HEX); Serial.write('.');
    Serial.print(s);
  }
  Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
}

/* Input data for testing
  Same data is stored in input_data.bin file, to verify the result, run hash sum on your PC
  and compare the result with this sketch
  $ sha1sum input_data.bin
  9f9da10ec23735930089a8f89b34f7b5d267903e
  $ sha224sum input_data.bin
  68abe34d09a758be6b2fb3a7a997983a639687099d35406f927a5cc5
  $ sha256sum input_data.bin
  75cfb39b62c474921e2aad979c210f8b69180a9d58e9f296a4b9904ae6e7aa40
  $ sha512sum input_data.bin
  e3979c6296e282af04619992f71addfefd118be26626cedd715edced36b87058f868b316e725b24e1e7f661ce2935e44ba4deea62afa3e13188071403a2f1463
*/

uint8_t input_data[] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0x65, 0xa2, 0x32, 0xd6, 0xbc, 0xd0, 0xf9, 0x39, 0xed, 0x1f, 0xe1, 0x28, 0xc1, 0x3b, 0x0e, 0x1b
}, sha1_result[] = {
  0x9f, 0x9d, 0xa1, 0x0e, 0xc2, 0x37, 0x35, 0x93,
  0x00, 0x89, 0xa8, 0xf8, 0x9b, 0x34, 0xf7, 0xb5,
  0xd2, 0x67, 0x90, 0x3e
}, sha224_result[] = {
  0x68, 0xab, 0xe3, 0x4d, 0x09, 0xa7, 0x58, 0xbe,
  0x6b, 0x2f, 0xb3, 0xa7, 0xa9, 0x97, 0x98, 0x3a,
  0x63, 0x96, 0x87, 0x09, 0x9d, 0x35, 0x40, 0x6f,
  0x92, 0x7a, 0x5c, 0xc5
}, sha256_result[] = {
  0x75, 0xcf, 0xb3, 0x9b, 0x62, 0xc4, 0x74, 0x92,
  0x1e, 0x2a, 0xad, 0x97, 0x9c, 0x21, 0x0f, 0x8b,
  0x69, 0x18, 0x0a, 0x9d, 0x58, 0xe9, 0xf2, 0x96,
  0xa4, 0xb9, 0x90, 0x4a, 0xe6, 0xe7, 0xaa, 0x40
}, sha512_result[] = {
  0xe3, 0x97, 0x9c, 0x62, 0x96, 0xe2, 0x82, 0xaf,
  0x04, 0x61, 0x99, 0x92, 0xf7, 0x1a, 0xdd, 0xfe,
  0xfd, 0x11, 0x8b, 0xe2, 0x66, 0x26, 0xce, 0xdd,
  0x71, 0x5e, 0xdc, 0xed, 0x36, 0xb8, 0x70, 0x58,
  0xf8, 0x68, 0xb3, 0x16, 0xe7, 0x25, 0xb2, 0x4e,
  0x1e, 0x7f, 0x66, 0x1c, 0xe2, 0x93, 0x5e, 0x44,
  0xba, 0x4d, 0xee, 0xa6, 0x2a, 0xfa, 0x3e, 0x13,
  0x18, 0x80, 0x71, 0x40, 0x3a, 0x2f, 0x14, 0x63
};

void test_result(uint32_t* result, uint8_t* expected, uint8_t result_len) {
  Serial.println("Produced:");
  hexDump((uint8_t*)result, result_len);
  Serial.println("Expected:");
  hexDump((uint8_t*)expected, result_len);
  if (memcmp(expected, (uint8_t*)result, result_len) == 0) Serial.println("Match!");
  else Serial.println("Fail [x]!");
}

void test_hash(uint32_t mode, const char* modestr) {
  uint32_t result[16];
  uint8_t result_len; // depending on Hash mode
  myHash.begin(mode);
  hexDump((uint8_t*) input_data,  sizeof(input_data));
  myHash.update(input_data, sizeof(input_data));
  result_len = myHash.end(result);
  Serial.print(" ");
  Serial.flush();
  Serial.println(modestr);
  if (CRYS_HASH_SHA1_mode == mode) test_result(result, sha1_result, result_len);
  else if (CRYS_HASH_SHA224_mode == mode) test_result(result, sha224_result, result_len);
  else if (CRYS_HASH_SHA256_mode == mode) test_result(result, sha256_result, result_len);
  else if (CRYS_HASH_SHA512_mode == mode) test_result(result, sha512_result, result_len);
  Serial.println();
  Serial.flush();
}

void setup() {
  Serial.begin(115200);
  time_t timeout = millis();
  while (!Serial) {
    if ((millis() - timeout) < 5000) {
      delay(100);
    } else {
      break;
    }
  }
  Serial.println("\nnRF AES test");
  Serial.print(" * Lib begin");
  SaSi_LibInit();
  Serial.println(" done!");
  Serial.print(" * AES begin");
  aes.begin();
  Serial.println(" done!");
  Serial.print(" * RND begin");
  rnd.begin();
  Serial.println(" done!");
}

void loop() {
  char *msg = "Hello user! This is a plain text string!";
  // please note dear reader – and you should RTFM – that this string's length isn't a multiple of 16.
  // but I am foolish that way.
  uint8_t msgLen = strlen(msg);
  // A function that calculates the required length. √
  uint8_t myLen = aes.blockLen(msgLen);
  char encBuf[myLen] = {0}; // Let's make sure we have enough space for the encrypted string
  char decBuf[myLen] = {0}; // Let's make sure we have enough space for the decrypted string
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);
  uint8_t pKey[16] = {0};
  uint8_t pKeyLen = 16;
  rnd.generate(pKey, 16); // use the CC310 to generate 16 random numbers
  Serial.println("pKey:");
  hexDump(pKey, 16);
  uint8_t IV[16] = {0};
  int rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ecbMode);
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ecbMode);
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  rnd.generate(IV, 16); // use the CC310 to generate 16 random numbers
  Serial.println("IV:");
  hexDump(IV, 16);
  rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.cbcMode);
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.cbcMode);
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  // The IV, after all the encryption rounds, should be preserved and communicated
  // to the party that needs to decrypt the cipher
  rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ctrMode);
  Serial.println("CTR Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ctrMode);
  Serial.println("CTR Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  test_hash(CRYS_HASH_SHA1_mode, "SHA-1");
  test_hash(CRYS_HASH_SHA224_mode, "SHA-224");
  test_hash(CRYS_HASH_SHA256_mode, "SHA-256");
  test_hash(CRYS_HASH_SHA512_mode, "SHA-512");
  // Note: SHA384 and MD5 currently cause hardfault
  // test_hash(CRYS_HASH_SHA384_mode, "SHA384");
  // test_hash(CRYS_HASH_MD5_mode, "MD5");
  delay(10000);
}
