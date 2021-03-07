#ifndef MODES_H_
#define MODES_H_

#define MODE_ECB 1
#define MODE_CBC 2
#define MODE_CTR 3

void increment_ctr(byte [NB4]);
void enc_mode_ecb(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const int NR);
void dec_mode_ecb(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const int NR);
void enc_mode_cbc(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const byte iv[NB4], const int NR);
void dec_mode_cbc(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const byte iv[NB4], const int NR);
void enc_mode_ctr(FILE *in, FILE *out, const word32 key[MAX_WORDS_K], const byte iv[NB4], const int NR);

#endif /* MODES_H_ */
