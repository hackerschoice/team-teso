#ifdef UNIX_LCN

/*  type definitions for utility servers  
	-unix flavour */


#define uint8	unsigned char
#define uint16	unsigned short
#define uint32	unsigned int
#define int8	char
#define int16	short
#define int32	int

#else

/*  type definitions for utility servers  
	-PC flavour */


#define uint8	unsigned char
#define uint16	unsigned int
#define uint32	unsigned long
#define int8	char
#define int16	int
#define int32	long
#define uint	unsigned int

#endif
