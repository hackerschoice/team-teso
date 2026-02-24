#ifndef __rc4_h__
#define __rc4_h__

typedef struct {
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
} rc4_key;

typedef struct {
	unsigned char *ptr;
	int stream_len;
} rc4_stream;

void prepare_key(unsigned char *, unsigned int, rc4_key *);
void rc4(unsigned char *, unsigned int, rc4_key *, unsigned int);
void my_swap_byte(unsigned char *,unsigned char *);

#endif

