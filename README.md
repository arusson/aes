# AES implementation in C

This project is the implementation of the Advanced Encryption Standard (AES), according to the standard [FIPS-197](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf).
Some of the ideas used come from the book [The Design of Rijndael: AES - The Advanced Encryption Standard](https://doi.org/10.1007/978-3-662-04722-4), by the authors of the Rijndael algorithm which is the basis of AES.

This coding project was done in 2017 and it is not advised to use it in production as no protection mechanism against side-channel attacks is included.

## Install

Download the repository and run the command
```bash
make
```

The compilation uses the following flags:
```bash
-Wall -Wextra -ansi -pedantic -O3
```

## Command

The binary to encrypt/decrypt files is "aes_exec". The options are:

```
-e | -d
    (required) The option -e to encrypt, and -d to decrypt.
               It must be followed by the mode:
     	       ecb    cbc    ctr

-i
    (required) It is followed with the name of the input file
               to encrypt/decrypt.

-k
    (required) It is followed with the key written in hexadecimal.
    	         The key must be 128, 192 or 256 bits.

-I
    (required) This option is only for CBC and CTR mode.
               It is followed by the IV (initial vector in CBC mode,
               or initial counter in CTR mode).
               The IV must be 128 bits.
             
-o
    (optional) Followed by the name of the output file.
               If this option is not used, the output file
               will be the same name as input file with ".enc"
               or ".dec" added at the end.
```

## Examples

To encrypt a file named secret.txt in ECB mode with a 128 bits key:

```bash
./aes_exec -i secret.txt -o secret.enc -e ecb -k 000102030405060708090a0b0c0d0e0f
```

To decrypt a file named secretfile in CBC mode with a 128 bits key and an IV:

```bash
./aes_exec -i secretfile -d cbc -k 000102030405060708090a0b0c0d0e0f -I 00112233445566778899aabbccddeeff
```

The decrypted file will be named secretfile.dec

