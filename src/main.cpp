#include <Arduino.h>

// ** NEW ADDITIONS FOR TWEETNACL ENCRYPTION LIBRARY **
//
//   Important - modify the two ramdom files as follows:
//   libdeps\esp32dev\tweetnacl_esp8266-master\randombytes.h
//      // Comment out these lines:
//      // #ifndef randombytes_implementation
//      // #define randombytes_implementation "infiniteloop"
//      // #endif
//   libdeps\esp32dev\tweetnacl_esp8266-master\randombytes.c
//      #include <esp32-hal.h>
//      //while(1); (Temporary replacement of random code)
//      for (unsigned long long i = 0; i < xlen; i++) {
//        // Works if the wifi/bt radio is active
//        x[i] = (unsigned) esp_random();
//      }

/////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////         DEFINITIONS           ///////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////

#include <randombytes.h>
#include <tweetnacl.h>
#include <tweetnacl_original.h>

#define TINY_GSM_DEBUG Serial


// For printing crypto strings
void displayStringAsHex( const char * text, int bytelen, unsigned char * bytedata ) {
  TINY_GSM_DEBUG.print( text);
  TINY_GSM_DEBUG.print(" (");
  TINY_GSM_DEBUG.print( bytelen);
  TINY_GSM_DEBUG.print(" char): ");
  for (int i = 0; i < bytelen; i++) { 
    TINY_GSM_DEBUG.print( (unsigned int)(byte)bytedata[i], 16);
    TINY_GSM_DEBUG.print(" "); 
  }
  TINY_GSM_DEBUG.println();
}

void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
  /////////////////////////////////////////////////////////////////////////////////////////////
  //                                    TweetNaCl Demo
  /////////////////////////////////////////////////////////////////////////////////////////////

  // Crypto use requires a random source
  // library code has been hacked to use Arduino random - ** obviously unsuitable **
  // Initialise it to be deterministic for testing only:
  randomSeed(0);

  // Perf timing
  unsigned long starttime;

  /////////////////////////////////////////////////////////////////////////////////////////////
  //                                    Get key pairs
  /////////////////////////////////////////////////////////////////////////////////////////////

  TINY_GSM_DEBUG.println(F("\nGet key pair A." ));
  unsigned char a_public_key[crypto_box_PUBLICKEYBYTES];
  unsigned char a_secret_key[crypto_box_SECRETKEYBYTES];

  starttime = millis();
  crypto_box_keypair(a_public_key, a_secret_key);
  TINY_GSM_DEBUG.print("Millis: ");
  TINY_GSM_DEBUG.println(millis()-starttime);

  displayStringAsHex( "A Public Key", crypto_box_PUBLICKEYBYTES, a_public_key );
  displayStringAsHex( "A Private Key", crypto_box_SECRETKEYBYTES, a_secret_key );

  TINY_GSM_DEBUG.println(F("\nGet key pair B." ));
  unsigned char b_public_key[crypto_box_PUBLICKEYBYTES];
  unsigned char b_secret_key[crypto_box_SECRETKEYBYTES];

  starttime = millis();
  crypto_box_keypair(b_public_key, b_secret_key);
  TINY_GSM_DEBUG.print("Millis: ");
  TINY_GSM_DEBUG.println(millis()-starttime);

  displayStringAsHex( "B Public Key", crypto_box_PUBLICKEYBYTES, b_public_key );
  displayStringAsHex( "B Private Key", crypto_box_SECRETKEYBYTES, b_secret_key );

  /////////////////////////////////////////////////////////////////////////////////////////////
  //                                    Encrypt
  /////////////////////////////////////////////////////////////////////////////////////////////


  // Message to encrypt
  const char *plaintext = "01234567890";
    displayStringAsHex( "To encode", strlen(plaintext), (unsigned char *)plaintext );

  // Nonce
  unsigned char nonce[crypto_box_NONCEBYTES]; // 24 bytes
  randombytes(nonce, crypto_box_NONCEBYTES);
  displayStringAsHex( "Nonce", crypto_box_NONCEBYTES, (unsigned char *)nonce );

  TINY_GSM_DEBUG.print(F("\nNonce Size: " ));
  TINY_GSM_DEBUG.println(crypto_box_NONCEBYTES);
  TINY_GSM_DEBUG.print(F("\nZero Size: " ));
  TINY_GSM_DEBUG.println(crypto_box_ZEROBYTES);

  long psize = crypto_box_ZEROBYTES + strlen(plaintext);
  unsigned char *padded = (unsigned char *) malloc(psize);
  if (padded == NULL)  TINY_GSM_DEBUG.println(F("\nMalloc failed!") );
  memset(padded, 0, crypto_box_ZEROBYTES); // 32 bytes!
  memcpy(padded + crypto_box_ZEROBYTES, plaintext, strlen(plaintext));

  // Output
  unsigned char *encrypted = (unsigned char *)calloc(psize, sizeof(unsigned char));
  if (encrypted == NULL) TINY_GSM_DEBUG.println(F("\nCalloc failed!") );

  // Encrypt
  TINY_GSM_DEBUG.println(F("\nEncrypting." ));
  starttime = millis();
  crypto_box(encrypted, padded, psize, nonce, b_public_key, a_secret_key);
  TINY_GSM_DEBUG.print("Millis: ");
  TINY_GSM_DEBUG.println(millis()-starttime);
  displayStringAsHex( "(Encrypted & Padding)", psize, encrypted );
  free(padded);

  int encLen = psize - crypto_box_BOXZEROBYTES;
  unsigned char * encMsg = encrypted + crypto_box_BOXZEROBYTES;
  displayStringAsHex( "Encrypted", encLen, encMsg );

  /////////////////////////////////////////////////////////////////////////////////////////////
  //                                    Decrypt
  /////////////////////////////////////////////////////////////////////////////////////////////

  // Decrypt
  TINY_GSM_DEBUG.println(F("\nDecrypting: "));

  // The nonce is the same as transmitted
  displayStringAsHex( "Nonce", crypto_box_NONCEBYTES, nonce );
  
  long esize = encLen + crypto_box_BOXZEROBYTES;
  unsigned char *encryptedDec = (unsigned char *)malloc(esize);
  if (encryptedDec == NULL) TINY_GSM_DEBUG.println(F("\nMalloc failed!") );

  memset(encryptedDec, 0, crypto_box_BOXZEROBYTES);
  memcpy(encryptedDec + crypto_box_BOXZEROBYTES, encMsg, encLen);
  // Equivalently, esize - crypto_box_BOXZEROBYTES

  // Output
  unsigned char *message = (unsigned char *)calloc(esize, sizeof(unsigned char));
  if (message == NULL)  TINY_GSM_DEBUG.println(F("\nCalloc failed!") );

  starttime = millis();
  crypto_box_open(message, encryptedDec, esize, nonce, a_public_key, b_secret_key);
  TINY_GSM_DEBUG.print("Millis: ");
  TINY_GSM_DEBUG.println(millis()-starttime);
  displayStringAsHex( "(All Message)", esize, message );

  int decMsgSize = esize - crypto_box_ZEROBYTES;
  unsigned char *decMsg = message + crypto_box_ZEROBYTES;

  displayStringAsHex( "Result", decMsgSize, decMsg );
          
}

void loop() {
  delay(1000);
  TINY_GSM_DEBUG.print(".");
}
