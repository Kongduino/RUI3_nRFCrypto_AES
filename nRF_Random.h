#include "crys_rnd.h"

class nRFCrypto_Random {
  public:
    nRFCrypto_Random(void);
    bool begin(void);
    void end(void);
    CRYS_RND_State_t* getContext(void);
    bool addAdditionalInput(uint8_t* input, uint16_t size);
    bool reseed(void);
    bool generate(uint8_t* buf, uint16_t count);
    bool generateInRange(uint8_t* buf, uint32_t bitsize, uint8_t* max = NULL);
    // enterKAtMode() DisableKatMoe()
  private:
    CRYS_RND_State_t _state;
    bool _begun;
};

/* 
 * The MIT License (MIT)
 *
 * Copyright (c) 2020 Ha Thach (tinyusb.org) for Adafruit Industries
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

//------------- IMPLEMENTATION -------------//
nRFCrypto_Random::nRFCrypto_Random(void) {
  _begun = false;
}

bool nRFCrypto_Random::begin(void) {
  // skip if already called begin before
  if (_begun) return true;
  _begun = true;
  CRYS_RND_WorkBuff_t* workbuf = (CRYS_RND_WorkBuff_t*) malloc(sizeof(CRYS_RND_WorkBuff_t));
  //VERIFY(workbuf);
  uint32_t err = CRYS_RndInit(&_state, workbuf);
  free(workbuf);
  return err;
}

void nRFCrypto_Random::end(void) {
  // skipped if not begin-ed
  if (!_begun) return;
  _begun = false;
  uint32_t err = CRYS_RND_UnInstantiation(&_state);
}

CRYS_RND_State_t* nRFCrypto_Random::getContext(void) {
  return &_state;
}

bool nRFCrypto_Random::addAdditionalInput(uint8_t* input, uint16_t size) {
  return(CRYS_RND_AddAdditionalInput(&_state, input, size));
}

bool nRFCrypto_Random::reseed(void) {
  CRYS_RND_WorkBuff_t* workbuf = (CRYS_RND_WorkBuff_t*) malloc(sizeof(CRYS_RND_WorkBuff_t));
  // VERIFY(workbuf);
  uint32_t err = CRYS_RND_Reseeding(&_state, workbuf);
  //rtos_free(workbuf);
  free(workbuf);
  // VERIFY_ERROR(err, false);
  return true;
}

bool nRFCrypto_Random::generate(uint8_t* buf, uint16_t bufsize) {
  return CRYS_RND_GenerateVector(&_state, bufsize, buf);
}

bool nRFCrypto_Random::generateInRange(uint8_t* buf, uint32_t bitsize, uint8_t* max) {
  return CRYS_RND_GenerateVectorInRange(&_state, CRYS_RND_GenerateVector, bitsize, max, buf);
}
