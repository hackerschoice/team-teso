#include <linux/types.h>
#include "rc4.h"


/* originally implemented by <unknown> */
void
prepare_key(unsigned char *key_data_ptr, size_t key_data_len, rc4_key *key)
{
	unsigned char index1;
	unsigned char index2;
	unsigned char* state;
	short counter;

	state = &key->state[0];
	for(counter = 0; counter < 256; counter++)
	state[counter] = counter;
	key->x = 0;
	key->y = 0;
	index1 = 0;
	index2 = 0;
	for (counter = 0; counter < 256; counter++) {
		index2 = (key_data_ptr[index1] + state[counter] +
			index2) % 256;
		my_swap_byte(&state[counter], &state[index2]);

		index1 = (index1 + 1) % key_data_len;
	}
}


void
rc4(unsigned char *buffer_ptr, size_t buffer_len, rc4_key *key, unsigned int from)
{
   	unsigned char x;
	unsigned char y;
	unsigned char *state;
	unsigned char xorIndex;
	unsigned int counter;
	unsigned int j;

	x = key->x;
	y = key->y;

	state = &key->state[0];

	for (counter = 0; counter < from; ++counter) {
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		my_swap_byte(&state[x], &state[y]);
	}


	for (j = 0; j < buffer_len; ++j) {
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		my_swap_byte(&state[x], &state[y]);

		xorIndex = (state[x] + state[y]) % 256;
		buffer_ptr[j] ^= state[xorIndex];
	}
	
	key->x = x;
	key->y = y;
}


void my_swap_byte(unsigned char *a, unsigned char *b)
{
	unsigned char swapByte;

	swapByte = *a;
	*a = *b;
	*b = swapByte;
}


