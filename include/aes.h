#ifndef AES_H_
#define AES_H_

/* NB: number of columns in a state, the standard specifies 4 */

#define NB 4
#define NB2 8
#define NB3 12
#define NB4 16
#define MAX_BYTES_K 32
#define MAX_WORDS_K 8
#define MAX_WORDS_RK 60
#define AES_ROUNDS_128 10
#define AES_ROUNDS_192 12
#define AES_ROUNDS_256 14
#define AES_ENCRYPT 1
#define AES_DECRYPT 2

typedef uint8_t byte;
typedef uint32_t word32;

/* useful macros for AES */
#define TAKEBYTE(w,n) (byte)(((w)>>(24-8*n)) & 255)
#define ROTWORD(w) ((w)>>24) | ((w)<<8)
#define XTIME(b) ((b)<<1) ^ (((b)>>7)*0x1b)

void getu32(const byte *a, word32 *b);
void getu8(const word32 *a, byte *b);
void subWord(word32 *a);
void invMixColumn(word32 *col);
void keyExpansion(const word32 key[MAX_WORDS_K], word32 keys[MAX_WORDS_RK], const int NR);
void eqKeyExpansion(const word32 key[MAX_WORDS_K], word32 eq_keys[MAX_WORDS_RK], const int NR);
void encrypt_aes(const byte input[NB4], byte output[NB4], const word32 keys[MAX_WORDS_RK], const int NR);
void decrypt_aes(const byte input[NB4], byte output[NB4], const word32 eq_keys[MAX_WORDS_RK], const int NR);

#endif /* AES_H_ */
