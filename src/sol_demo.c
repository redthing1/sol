#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sol.h>

int main(int argc, char** argv) {
  if (argc != 3) {
    printf("Usage: %s <input> <key>\n", argv[0]);
    return 1;
  }
  // read input string from arg 0
  char* input = argv[1];

  // read key from arg 1
  char* key_st = argv[2];
  // sha256 hash the key
  unsigned char key[sol_crypto_hash_BYTES];
  sol_crypto_hash(key, (unsigned char*)key_st, strlen(key_st));

  // generate a random nonce
  unsigned char nonce[sol_crypto_secretbox_NONCEBYTES];
  sol_randombytes(nonce, sol_crypto_secretbox_NONCEBYTES);

  // create a buffer for the plaintext
  unsigned char plaintext[sol_crypto_secretbox_ZEROBYTES + strlen(input)];
  // copy the input into the plaintext buffer
  memset(plaintext, 0, sol_crypto_secretbox_ZEROBYTES);
  memcpy(plaintext + sol_crypto_secretbox_ZEROBYTES, input, strlen(input));

  // create a buffer for the ciphertext
  unsigned char ciphertext[sol_crypto_secretbox_ZEROBYTES + strlen(input)];
  // encrypt the plaintext
  sol_crypto_secretbox(ciphertext, plaintext, sol_crypto_secretbox_ZEROBYTES + strlen(input), nonce, key);

  // print the parameters
  printf("key: ");
  for (size_t i = 0; i < sol_crypto_hash_sha256_BYTES; i++) {
    printf("%02x", key[i]);
  }
  printf("\n");
  printf("nonce: ");
  for (size_t i = 0; i < sol_crypto_secretbox_NONCEBYTES; i++) {
    printf("%02x", nonce[i]);
  }
  printf("\n");

  // print the original plaintext
  printf("plaintext: ");
  for (size_t i = sol_crypto_secretbox_ZEROBYTES; i < sol_crypto_secretbox_ZEROBYTES + strlen(input); i++) {
    printf("%02x", plaintext[i]);
  }
  printf("\n");

  printf("ciphertext: ");
  for (size_t i = sol_crypto_secretbox_ZEROBYTES; i < sol_crypto_secretbox_ZEROBYTES + strlen(input); i++) {
    printf("%02x", ciphertext[i]);
  }
  printf("\n");

  // now try to decrypt the ciphertext
  unsigned char decrypted[sol_crypto_secretbox_ZEROBYTES + strlen(input)];
  if (sol_crypto_secretbox_open(decrypted, ciphertext, sol_crypto_secretbox_ZEROBYTES + strlen(input), nonce, key) !=
      0) {
    printf("decryption failed!\n");
    return 1;
  }

  // print the decrypted plaintext
  printf("plaintext: ");
  for (size_t i = sol_crypto_secretbox_ZEROBYTES; i < sol_crypto_secretbox_ZEROBYTES + strlen(input); i++) {
    printf("%02x", decrypted[i]);
  }
  printf("\n");

  // verify that the decrypted plaintext matches the original plaintext
  if (memcmp(plaintext, decrypted, sol_crypto_secretbox_ZEROBYTES + strlen(input)) != 0) {
    printf("decrypted plaintext does not match original plaintext!\n");
    return 1;
  }

  printf("decryption succeeded!\n");

  return 0;
}
