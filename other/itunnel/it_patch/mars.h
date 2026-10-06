typedef unsigned long int u4byte;
#define rotl(x,n)   (((x) << ((u4byte)(n))) | ((x) >> (32 - (u4byte)(n))))
#define rotr(x,n)   (((x) >> ((u4byte)(n))) | ((x) << (32 - (u4byte)(n))))
#define byteswap(x)     ((rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00))

extern void encrypt(const u4byte *, u4byte *);
extern void decrypt(const u4byte *, u4byte *);
extern u4byte *set_key (const u4byte *, const u4byte);

extern u4byte l_key[40];
