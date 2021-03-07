#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "aes.h"
#include "modes.h"


int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind, opterr, optopt;


void print_instructions(const char *msg) {
  if (msg != NULL) {
    printf("Error: %s\n", msg);
  }
  printf("The options are:\n"
         " -e value     Encrypt, value is ecb, cbc or ctr\n"
         " -d value     Decrypt, value is ecb, cbc or ctr\n"
         " -i value     Input, value is source file name\n"
         " -o value     Output (optional), value is destination file name file\n"
         " -k value     Key, value in hexadecimal (128, 192 or 256 bits)\n"
         " -I value     IV, value in hexadecimal (cbc and ctr mode only)\n");
}


int main(int argc, char *argv[]) {
  
  FILE *in, *out;
  int keysize, i, mode, NR;
  byte iv[NB4];
  word32 key[MAX_WORDS_K];
  char hex_part[9] = "";
  
  struct {
    int encdec;
    char *mode_str;
    char *key_str;
    char *iv_str;
    char *in_filename;
    char *out_filename;
  } arguments;
  
  int opt = 0;
  char options[] = "e:d:k:I:i:o:";
  
  arguments.encdec  = -1;
  arguments.mode_str = NULL;
  arguments.key_str = NULL;
  arguments.iv_str = NULL;
  arguments.in_filename = NULL;
  arguments.out_filename = NULL;
  
  
  /* read arguments */
  opt = getopt(argc, argv, options);
  while (opt != -1) {
    switch (opt) {
      
    case 'e':
      if (arguments.encdec == -1) {
        arguments.encdec = AES_ENCRYPT;
        arguments.mode_str = optarg;
      }
      else {
        print_instructions("-e and -d cannot be used at the same time");
        exit(EXIT_FAILURE);
      }
      break;
      
    case 'd':
      if (arguments.encdec == -1) {
        arguments.encdec = AES_DECRYPT;
        arguments.mode_str = optarg;
      }
      else {
        print_instructions("-e and -d cannot be used at the same time");
        exit(EXIT_FAILURE);
      }
      break;
      
    case 'k':
      arguments.key_str = optarg;
      break;
      
    case 'I':
      arguments.iv_str = optarg;
      break;
      
    case 'i':
      arguments.in_filename = optarg;
      break;
      
    case 'o':
      arguments.out_filename = optarg;
      break;
      
    case '?':
      print_instructions("options are missing");
      exit(EXIT_FAILURE);
      break;
    }
    opt = getopt(argc, argv, options);
  }
  
  
  /* handling  arguments */
  if (arguments.encdec == -1) {
    print_instructions("-e or -d not specified");
    exit(EXIT_FAILURE);
  }
  
  /* mode */
  if (strncmp(arguments.mode_str, "cbc", 3) == 0) {
    mode = MODE_CBC;
  }
  else if (strncmp(arguments.mode_str, "ctr", 3) == 0) {
    mode = MODE_CTR;
  }
  else if (strncmp(arguments.mode_str, "ecb", 3) == 0) {
    mode = MODE_ECB;
  }
  else {
    print_instructions("mode missing or wrong.");
    exit(EXIT_FAILURE);
  }
  
  /* open files */
  in = fopen(arguments.in_filename, "r");
  if (in == NULL) {
    fprintf(stderr, "Error: cannot open source file.\n");
    exit(EXIT_FAILURE);
  }

  if (arguments.out_filename == NULL) {
    arguments.out_filename = malloc((strlen(arguments.in_filename) + 5)*sizeof(char));
    strcpy(arguments.out_filename, arguments.in_filename);
    
    if (arguments.encdec == AES_ENCRYPT) {
      strcat(arguments.out_filename, ".enc");
    }
    else {
      strcat(arguments.out_filename, ".dec");
    }
    
    out = fopen(arguments.out_filename, "w");
    free(arguments.out_filename);
  }
  else {
    out = fopen(arguments.out_filename, "w");
  }
  
  if (out == NULL) {
    fprintf(stderr, "Error: cannot open destination file.\n");
    exit(EXIT_FAILURE);
  }
  
  /* read key and its size length */
  if (arguments.key_str == NULL) {
    keysize = -1;
  }
  else {
    keysize = strlen(arguments.key_str);
  }
  switch (keysize) {
  case 32:
    NR = AES_ROUNDS_128;
    break;
    
  case 48:
    NR = AES_ROUNDS_192;
    break;
    
  case 64:
    NR = AES_ROUNDS_256;
    break;
    
  case -1:
    print_instructions("key is missing.");
    exit(EXIT_FAILURE);
  default:
    print_instructions("wrong size of key.");
    exit(EXIT_FAILURE);
    break;
  }
  keysize /= 8;
  
  for (i = 0; i < keysize; i++) {
    strncpy(hex_part, &arguments.key_str[8*i], 8);
    key[i] = strtoul(hex_part, NULL, 16);
  }
  hex_part[2] = '\0';
  
  
  /* encryption/decryption */
  switch(mode) {
    
  case MODE_ECB:
    if (arguments.encdec == AES_ENCRYPT) {
      enc_mode_ecb(in, out, key, NR);
    }
    else {
      dec_mode_ecb(in, out, key, NR);
    }
    break;
    
  case MODE_CBC:
    
    /* check IV */
    if (arguments.iv_str == NULL || strlen(arguments.iv_str) != 2*NB4) {
      print_instructions("iv not specified or wrong.");
      exit(EXIT_FAILURE);
    }
    
    for (i = 0; i < NB4; i++) {
      strncpy(hex_part, &arguments.iv_str[2*i], 2);
      iv[i] = strtoul(hex_part, NULL, 16);
    }
    
    if (arguments.encdec == AES_ENCRYPT) {
      enc_mode_cbc(in, out, key, iv, NR);
    }
    else {
      dec_mode_cbc(in, out, key, iv, NR);
    }
    break;
    
  case MODE_CTR:
    
    /* check IV */
    if (arguments.iv_str == NULL || strlen(arguments.iv_str) != 2*NB4) {
      print_instructions("iv not specified or wrong.");
      exit(EXIT_FAILURE);
    }
    
    for (i = 0; i < NB4; i++) {
      strncpy(hex_part, &arguments.iv_str[2*i], 2);
      iv[i] = strtoul(hex_part, NULL, 16);
    }
    
    enc_mode_ctr(in, out, key, iv, NR);
    break;
    
  default:
    /* impossible */
    break;
  }
  
  fclose(in);
  fclose(out);
  
  return 0;
}
