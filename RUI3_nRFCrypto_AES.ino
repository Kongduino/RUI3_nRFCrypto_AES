#include <cstring>
#include "/Users/dda/Library/Arduino15/packages/rak_rui/hardware/nrf52/3.2.0/cores/nRF5/external/nRF5_SDK/nRF5_SDK_17.0.2_d674dde/external/nrf_cc310/include/ssi_aes.h"
#include "/Users/dda/Library/Arduino15/packages/rak_rui/hardware/nrf52/3.2.0/cores/nRF5/external/nRF5_SDK/nRF5_SDK_17.0.2_d674dde/external/nrf_cc310/include/sns_silib.h"

class nRFCrypto_AES {
  public:
    nRFCrypto_AES(void);
    bool begin(void);
    void end(void);
    int Process(
      char *msg, uint8_t msgLen, uint8_t *IV, uint8_t *pKey, uint8_t pKeyLen,
      char *retBuf, SaSiAesEncryptMode_t modeFlag, SaSiAesOperationMode_t opMode);
    SaSiAesEncryptMode_t encryptFlag = (SaSiAesEncryptMode_t) 0; // SASI_AES_ENCRYPT
    SaSiAesEncryptMode_t decryptFlag = (SaSiAesEncryptMode_t) 1; // SASI_AES_DECRYPT
    SaSiAesOperationMode_t ecbMode = (SaSiAesOperationMode_t) 0; // SASI_AES_MODE_ECB
    SaSiAesOperationMode_t cbcMode = (SaSiAesOperationMode_t) 1; // SASI_AES_MODE_CBC
    SaSiAesOperationMode_t ctrMode = (SaSiAesOperationMode_t) 3; // SASI_AES_MODE_CTR
    uint8_t blockLen(uint8_t);
  private:
    bool _begun;
    SaSiAesPaddingType_t _paddingType = (SaSiAesPaddingType_t) 0; // SASI_AES_PADDING_NONE
    SaSiAesKeyType_t _userKey = (SaSiAesKeyType_t) 0; // SASI_AES_USER_KEY
};

nRFCrypto_AES::nRFCrypto_AES(void) {
  _begun = false;
}

bool nRFCrypto_AES::begin() {
  if (_begun == true) return true;
  _begun = false;
  int ret = SaSi_LibInit();
  if (ret == SA_SILIB_RET_OK) _begun = true;
  return (ret == SA_SILIB_RET_OK);
}

void nRFCrypto_AES::end() {
  _begun = false;
  SaSi_LibFini();
}

int nRFCrypto_AES::Process(
  char *msg, uint8_t msgLen, uint8_t *IV, uint8_t *pKey, uint8_t pKeyLen,
  char *retBuf, SaSiAesEncryptMode_t modeFlag, SaSiAesOperationMode_t opMode) {
  /*
    msg:    the message you want to encrypt. does not need to be a multiple of 16 bytes.
    msgLen:   its length
    IV:     the IV (16 bytes) for CBC
    pKey:   the key (16/24/32 bytes)
    pKeyLen:  its length
    retBuf:   the return buffer. MUST be a multiple of 16 bytes.
    modeFlag: encryptFlag / decryptFlag
    opMode:   ecbMode / cbcMode / ctrMode
  */
  if (!_begun) return -1;
  int ret = SaSi_LibInit();
  if (ret != SA_SILIB_RET_OK) return -2;
  if (pKeyLen % 8 != 0) return -3;
  if (pKeyLen < 16) return -3;
  if (pKeyLen > 32) return -3;
  SaSiAesUserContext_t pContext;
  SaSiError_t err = SaSi_AesInit(&pContext, modeFlag, opMode, _paddingType);
  SaSiAesUserKeyData_t keyData;
  keyData.pKey = pKey;
  keyData.keySize = pKeyLen;
  err = SaSi_AesSetKey(&pContext, _userKey, &keyData, sizeof(keyData));
  if (err != SASI_OK) return -4;
  uint8_t cx, ln = msgLen, ptLen;
  ptLen = blockLen(msgLen);
  uint8_t modulo = ptLen % 16;
  if (modulo > 0) modulo = 16 - modulo;
  char pDataIn[ptLen] = {modulo};
  // Padding included!
  memcpy(pDataIn, msg, msgLen);
  size_t dataOutBuffSize;
  memset(retBuf, 0, ptLen);
  if (ptLen > 16) {
    for (cx = 0; cx < ptLen - 16; cx += 16) {
      err = SaSi_AesBlock(&pContext, (uint8_t *) (pDataIn + cx), 16, (uint8_t *) (retBuf + cx));
      if (err != SASI_OK) return -5;
    }
    err = SaSi_AesFinish(&pContext, (size_t) 16, (uint8_t *) (pDataIn + cx), (size_t) 16, (uint8_t *) (retBuf + cx), &dataOutBuffSize);
    if (err != SASI_OK) return -6;
  } else {
    err = SaSi_AesBlock(&pContext, (uint8_t *) pDataIn, 16, (uint8_t *) retBuf);
    if (err != SASI_OK) return -5;
    err = SaSi_AesFinish(&pContext, (size_t) 0, (uint8_t *) (pDataIn), (size_t) 0, (uint8_t *) (retBuf), &dataOutBuffSize);
    if (err != SASI_OK) return -6;
  }
  return ptLen;
}

uint8_t nRFCrypto_AES::blockLen(uint8_t msgLen) {
  if (msgLen < 16) {
    return 16;
  } else {
    uint8_t modulo = 0, myLen;
    modulo = msgLen % 16;
    if (modulo != 0) {
      uint8_t x = (msgLen / 16);
      myLen = (x + 1) * 16;
      modulo = 16 - modulo;
    } else myLen = msgLen;
    return myLen;
  }
}

nRFCrypto_AES aes;

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
  SaSi_LibInit();
  Serial.println("\nnRF AES test");
  Serial.print(" * begin");
  aes.begin();
  Serial.println(" done!");
}
void loop() {
  char *msg = "Hello user! This is a plain text string!";
  // please note dear reader – and you should RTFM – that this string's length isn't a multiple of 16.
  // but I am foolish that way.
  uint8_t msgLen = strlen(msg);
  // A function that calculates the required length. √
  uint8_t myLen = aes.blockLen(msgLen);
  // Serial.println("myLen = " + String(myLen));
  char encBuf[myLen] = {0}; // Let's make sure we have enough space for the encrypted string
  char decBuf[myLen] = {0}; // Let's make sure we have enough space for the decrypted string
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);
  uint8_t pKey[16] = {
    0x6f, 0x22, 0x86, 0x74, 0x68, 0x6f, 0x46, 0x5c,
    0xb9, 0x6b, 0xe4, 0xea, 0x0b, 0xc6, 0xf7, 0x89
  };
  uint8_t pKeyLen = 16;
  // nRFCrypto.Random.generate(pKey, 16);
  // memcpy(pKey, "Ceci n'est pas u", 16);
  Serial.println("pKey:");
  hexDump(pKey, 16);
  uint8_t IV[16] = {
    0x9f, 0x98, 0x47, 0x48, 0xa0, 0x40, 0x49, 0x4a,
    0x8b, 0xc5, 0xeb, 0xd8, 0x0e, 0x95, 0x88, 0xae
  };
  int rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ecbMode);
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ecbMode);
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  // nRFCrypto.Random.generate(IV, 16);
  Serial.println("IV:");
  hexDump(IV, 16);
  rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.cbcMode);
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.cbcMode);
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ctrMode);
  Serial.println("CTR Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ctrMode);
  Serial.println("CTR Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  delay(10000);
}
