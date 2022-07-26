#include <cstring>
#include "helper.h"
#include "nRF_AES.h"
#include "nRFCrypto_Chacha.h"
#include "nRF_Random.h"
#include "nRF_Hash.h"

long startTime;
bool rx_done = false;
double myFreq = 868000000;
uint16_t sf = 12, bw = 125, cr = 0, preamble = 8, txPower = 22;

void explainError(int, uint8_t);

void recv_cb(rui_lora_p2p_recv_t data) {
  rx_done = true;
  if (data.BufferSize == 0) {
    Serial.println("Empty buffer.");
    return;
  }
  char buff[92];
  sprintf(buff, "Incoming message, length: %d, RSSI: %d, SNR: %d", data.BufferSize, data.Rssi, data.Snr);
  Serial.println(buff);
  hexDump(data.Buffer, data.BufferSize);
}

void send_cb(void) {
  Serial.printf("P2P set Rx mode %s\r\n", api.lorawan.precv(65534) ? "Success" : "Fail");
}

nRFCrypto_AES aes;
nRFCrypto_Random rnd;
nRFCrypto_Hash myHash;
nRFCrypto_Chacha urara;

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
  Serial.begin(115200, RAK_CUSTOM_MODE);
  // RAK_CUSTOM_MODE disables AT firmware parsing
  delay(5000);
  uint8_t x = 5;
  while (x > 0) {
    Serial.printf("%d, ", x--);
    delay(500);
  } // Just for show
  Serial.println("0!");
  Serial.println("RAKwireless nRF Crypto");
  Serial.println("------------------------------------------------------");
  char HardwareID[16]; // nrf52840
  strcpy(HardwareID, api.system.chipId.get().c_str());
  Serial.printf("Hardware ID: %s\r\n", HardwareID);
  if (strcmp(HardwareID, "nrf52840") != 0) {
    Serial.printf("Wrong hardware: %s! This is not an nrf52840!", HardwareID);
    while (1);
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

  startTime = millis();
  Serial.println("P2P Start");
  Serial.printf("Hardware ID: %s\r\n", api.system.chipId.get().c_str());
  Serial.printf("Model ID: %s\r\n", api.system.modelId.get().c_str());
  Serial.printf("RUI API Version: %s\r\n", api.system.apiVersion.get().c_str());
  Serial.printf("Firmware Version: %s\r\n", api.system.firmwareVersion.get().c_str());
  Serial.printf("AT Command Version: %s\r\n", api.system.cliVersion.get().c_str());
  Serial.printf("Set Node device work mode %s\r\n", api.lorawan.nwm.set(0) ? "Success" : "Fail");
  Serial.printf("Set P2P mode frequency %3.3f: %s\r\n", (myFreq / 1e6), api.lorawan.pfreq.set(myFreq) ? "Success" : "Fail");
  Serial.printf("Set P2P mode spreading factor %d: %s\r\n", sf, api.lorawan.psf.set(sf) ? "Success" : "Fail");
  Serial.printf("Set P2P mode bandwidth %d: %s\r\n", bw, api.lorawan.pbw.set(bw) ? "Success" : "Fail");
  Serial.printf("Set P2P mode code rate 4/%d: %s\r\n", (cr + 5), api.lorawan.pcr.set(0) ? "Success" : "Fail");
  Serial.printf("Set P2P mode preamble length %d: %s\r\n", preamble, api.lorawan.ppl.set(8) ? "Success" : "Fail");
  Serial.printf("Set P2P mode tx power %d: %s\r\n", txPower, api.lorawan.ptp.set(22) ? "Success" : "Fail");
  api.lorawan.registerPRecvCallback(recv_cb);
  api.lorawan.registerPSendCallback(send_cb);
  Serial.printf("P2P set Rx mode %s\r\n", api.lorawan.precv(3000) ? "Success" : "Fail");
  // let's kick-start things by waiting 3 seconds.
}

void loop() {
  char *msg = "Hello user! This is a plain text string!        ";
  // please note dear reader – and you should RTFM – that this string's length isn't a multiple of 16.
  // but I am foolish that way.
  uint8_t msgLen = strlen(msg);
  // A function that calculates the required length. √
  uint8_t myLen = aes.blockLen(msgLen);
  char encBuf[myLen] = {0}; // Let's make sure we have enough space for the encrypted string
  char decBuf[myLen] = {0}; // Let's make sure we have enough space for the decrypted string
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);

  uint8_t pKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t pKeyLen = 16;
  rnd.generate(pKey, 16); // use the CC310 to generate 16 random numbers
  Serial.println("pKey:");
  hexDump(pKey, 16);

  uint8_t IV[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x88, 0x88, 0x88, 0x88, 0xc0, 0x00, 0x00, 0x00};
  uint8_t myIV[16];
  rnd.generate(IV, 16); // use the CC310 to generate 16 random numbers
  memcpy(myIV, IV, 16);

  int rslt = aes.Process(msg, msgLen, myIV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ecbMode);
  if (rslt < 0) {
    Serial.printf("Error %d Process ECB Encrypt", rslt);
    while (1);
  }
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, myIV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ecbMode);
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  memcpy(myIV, IV, 16);
  Serial.println("IV:");
  hexDump(myIV, 16);
  memset(encBuf, myLen, myLen);
  memset(decBuf, myLen, myLen);
  rslt = aes.Process(msg, msgLen, myIV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.cbcMode);
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, myIV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.cbcMode);
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  // The IV, after all the encryption rounds, should be preserved and communicated
  // to the party that needs to decrypt the cipher
  memcpy(myIV, IV, 16);
  Serial.println("IV:");
  hexDump(myIV, 16);
  memset(encBuf, myLen, myLen);
  memset(decBuf, myLen, myLen);
  rslt = aes.Process(msg, msgLen, myIV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ctrMode);
  Serial.println("CTR Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, myIV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ctrMode);
  Serial.println("CTR Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  // CHACHA
  uint8_t orgLen = msgLen;
  msgLen = 64;
  memset(decBuf, 0, msgLen);
  memset(encBuf, 0, msgLen);
  nRFCrypto_Chacha urara; // You need to speak Korean to understand this one ;-)
  urara.begin();
  CRYS_CHACHA_Nonce_t pNonce;
  CRYS_CHACHA_Key_t myKey;
  uint32_t initialCounter = 0;
  pKeyLen = 32;
  // We're going to pass a 44-byte array to the Process function:
  // The first 32 are the key, the next 12 the nonce.
  // The Process functions builds the CRYS_CHACHAUserContext_t, CRYS_CHACHA_Nonce_t and CRYS_CHACHA_Key_t objects itself.
  uint8_t temp[44];
  rnd.generate(temp, 44);
  Serial.println("myKey:");
  hexDump((uint8_t*)temp, pKeyLen);
  Serial.println("Nonce:");
  hexDump((uint8_t*)temp + 32, 12);

  // orig = our "plaintext"
  uint8_t orig[93];
  // enc = our "plaintext", then encrypted version (in place), then, hopefully the properly decoded version.
  uint8_t enc[93];
  rnd.generate(orig, 93);

  // First test with a block smaller than the minimum block size (64)
  Serial.println("\nOriginal [32]:");
  memcpy(enc, orig, 32);
  hexDump(enc, 32);
  rslt = urara.Process(enc, 32, temp, urara.encryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) {
    explainError(rslt, msgLen);
    return;
  } else {
    Serial.println("Chacha Encoded:");
    hexDump(enc, 64);
  }
  rslt = urara.Process(enc, 32, temp, urara.decryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) explainError(rslt, msgLen);
  else {
    Serial.println("Chacha Decoded (only the first 32 bytes count):");
    hexDump(enc, 64);
    if (memcmp(orig, enc, 32) == 0) Serial.println("Enc/Dec roud-trip successful!");
    else Serial.println("Enc/Dec roud-trip fail!");
  }

  // Second test with a block longer than the minimum block size (64)
  // and not a multiple of 64
  memcpy(enc, orig, 93);
  Serial.println("\nOriginal [93]:");
  hexDump(enc, 93);
  rslt = urara.Process(enc, 93, temp, urara.encryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) {
    explainError(rslt, msgLen);
    return;
  } else {
    Serial.println("Chacha Encoded:");
    hexDump(enc, 93);
  }
  rslt = urara.Process(enc, 93, temp, urara.decryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) explainError(rslt, msgLen);
  else {
    Serial.println("Chacha Decoded:");
    hexDump(enc, 93);
    if (memcmp(orig, enc, 93) == 0) Serial.println("Enc/Dec roud-trip successful!");
    else Serial.println("Enc/Dec roud-trip fail!");
  }


  test_hash(CRYS_HASH_SHA1_mode, "SHA-1");
  test_hash(CRYS_HASH_SHA224_mode, "SHA-224");
  test_hash(CRYS_HASH_SHA256_mode, "SHA-256");
  test_hash(CRYS_HASH_SHA512_mode, "SHA-512");
  // Note: SHA384 and MD5 currently cause hardfault
  // test_hash(CRYS_HASH_SHA384_mode, "SHA384");
  // test_hash(CRYS_HASH_MD5_mode, "MD5");
  Serial.printf("Try sleep %u ms..", 10000);
  api.system.sleep.all(10000);
  Serial.println("Wakeup..");
}
