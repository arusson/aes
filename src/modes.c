#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes.h"


/* increment counter for CTR mode */
void increment_ctr(byte counter[NB4]) {
  int i = NB4 - 1;
  while (i >= 0 && ++counter[i]==0) {
    i--;
  }
}


/* --------------- MODE ECB ---------------- */

void enc_mode_ecb(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const int NR) {
  word32 keys[MAX_WORDS_RK];
  byte plain[NB4], cipher[NB4], padding_value;
  int i, n;
  
  fseek(in, 0, SEEK_END);
  n = ftell(in);
  rewind(in);
  n %= NB4;
  padding_value = NB4 - n;

  keyExpansion(key, keys, NR);
  while (fread(plain, 1, NB4, in) == NB4) {
    encrypt_aes(plain, cipher, keys, NR);
    fwrite(cipher, 1, NB4, out);
  }
  for (i = n; i < NB4; i++) {
    plain[i] = padding_value;
  }
  encrypt_aes(plain, cipher, keys, NR);
  fwrite(cipher, 1, NB4, out);
}


void dec_mode_ecb(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const int NR) {
  word32 eq_keys[MAX_WORDS_RK];
  byte cipher[NB4], plain[NB4];
  int i, n;
  
  fseek(in, 0, SEEK_END);
  n = ftell(in);
  rewind(in);
  if (n % NB4 !=0) {
    fprintf(stderr, "Error: bad file, cannot be decrypted.\n");
    exit(EXIT_FAILURE);
  }
  n /= NB4;
  
  eqKeyExpansion(key, eq_keys, NR);
  for (i = 0; i < n - 1; i++) {
    fread(cipher, 1, NB4, in);
    decrypt_aes(cipher, plain, eq_keys, NR);
    fwrite(plain, 1, NB4, out);
  }
  fread(cipher, 1, NB4, in);
  decrypt_aes(cipher, plain, eq_keys, NR);
  fwrite(plain, 1, NB4-plain[NB4 - 1], out);
}
  


/* --------------------- MODE CBC ------------------------- */

void enc_mode_cbc(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const byte iv[NB4], const int NR) {
  word32 keys[MAX_WORDS_RK];
  byte plain[NB4], cipher[NB4], padding_value;
  int i, n;
    
  fseek(in, 0, SEEK_END);
  n = ftell(in);
  rewind(in);
  n %= NB4;
  padding_value = NB4 - n;

  keyExpansion(key, keys, NR);

  for (i = 0; i < NB; i++) {
    cipher[i]       = iv[i];
    cipher[i + NB]  = iv[i + NB];
    cipher[i + NB2] = iv[i + NB2];
    cipher[i + NB3] = iv[i + NB3];
  }
  
  while (fread(plain, 1, NB4, in) == NB4) {
    for (i = 0; i < NB; i++) {
      plain[i]       ^= cipher[i];
      plain[i + NB]  ^= cipher[i + NB];
      plain[i + NB2] ^= cipher[i + NB2];
      plain[i + NB3] ^= cipher[i + NB3];
    }
    encrypt_aes(plain, cipher, keys, NR);
    fwrite(cipher, 1, NB4, out);
  }

  for (i = n; i < NB4; i++) {
    plain[i] = padding_value;
  }
  for (i = 0; i < NB; i++) {
    plain[i]       ^= cipher[i];
    plain[i + NB]  ^= cipher[i + NB];
    plain[i + NB2] ^= cipher[i + NB2];
    plain[i + NB3] ^= cipher[i + NB3];
  }
  encrypt_aes(plain, cipher, keys, NR);
  fwrite(cipher, 1, NB4, out);
}


void dec_mode_cbc(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const byte iv[NB4], const int NR) {
  word32 eq_keys[MAX_WORDS_RK];
  byte plain[NB4], cipher[NB4], prec_cipher[NB4];
  int i, j, n;
  
  fseek(in, 0, SEEK_END);
  n = ftell(in);
  rewind(in);
  if ((n % NB4) !=0) {
    fprintf(stderr, "Error: bad file, cannot be decrypted.\n");
    exit(EXIT_FAILURE);
  }
  n /= NB4;

  eqKeyExpansion(key, eq_keys, NR);
  
  for (i = 0; i < NB; i++) {
    prec_cipher[i]       = iv[i];
    prec_cipher[i + NB]  = iv[i + NB];
    prec_cipher[i + NB2] = iv[i + NB2];
    prec_cipher[i + NB3] = iv[i + NB3];
  }

  for (i = 0; i < n - 1; i++) {
    fread(cipher, 1, NB4, in);
    decrypt_aes(cipher, plain, eq_keys, NR);
    for (j = 0; j < NB; j++) {
      plain[j]       ^= prec_cipher[j];
      plain[j + NB]  ^= prec_cipher[j + NB];
      plain[j + NB2] ^= prec_cipher[j + NB2];
      plain[j + NB3] ^= prec_cipher[j + NB3];
      prec_cipher[j]       = cipher[j];
      prec_cipher[j + NB]  = cipher[j + NB];
      prec_cipher[j + NB2] = cipher[j + NB2];
      prec_cipher[j + NB3] = cipher[j + NB3];
    }
    fwrite(plain, 1, NB4, out);  
  }
  fread(cipher, 1, NB4, in);
  decrypt_aes(cipher, plain, eq_keys, NR);
  for (j = 0; j < NB; j++) {
    plain[j]       ^= prec_cipher[j];
    plain[j + NB]  ^= prec_cipher[j + NB];
    plain[j + NB2] ^= prec_cipher[j + NB2];
    plain[j + NB3] ^= prec_cipher[j + NB3];
  }
  fwrite(plain, 1, NB4 - plain[NB4 - 1], out);
}



/* ----------------------- MODE CTR ----------------------- */

void enc_mode_ctr(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const byte iv[NB4], const int NR) {
  word32 keys[MAX_WORDS_RK];
  byte counter[NB4], counter_cipher[NB4], plain[NB4];
  int i, n;
  
  fseek(in, 0, SEEK_END);
  n = ftell(in);
  rewind(in);
  n %= NB4;

  keyExpansion(key, keys, NR);
  
  for (i = 0; i < NB; i++) {
    counter[i]     = iv[i];
    counter[i + NB]  = iv[i + NB];
    counter[i + NB2] = iv[i + NB2];
    counter[i + NB3] = iv[i + NB3];
  }
    
  while (fread(plain, 1, NB4, in) == NB4) {
    encrypt_aes(counter, counter_cipher, keys, NR);
    increment_ctr(counter);
    for (i = 0; i < NB; i++) {
      plain[i]       ^= counter_cipher[i];
      plain[i + NB]  ^= counter_cipher[i + NB];
      plain[i + NB2] ^= counter_cipher[i + NB2];
      plain[i + NB3] ^= counter_cipher[i + NB3];
    }
    fwrite(plain, 1, NB4, out);
  }
  if (n != 0) {
    encrypt_aes(counter, counter_cipher, keys, NR);
    for (i = 0; i < n; i++) {
      plain[i] ^= counter_cipher[i];
    }
    fwrite(plain, 1, n, out);
  }
}

