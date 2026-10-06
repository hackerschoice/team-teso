/*
 * Abstract Syntax Notation One, ASN.1
 * As defined in ISO/IS 8824 and ISO/IS 8825
 * This implements a subset of the above International Standards that
 * is sufficient to implement SNMP.
 *
 * Encodes abstract data types into a machine independent stream of bytes.
 *
 */
/**********************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
#ifdef KINETICS
#include "gw.h"
#endif

#if (defined(unix) && !defined(KINETICS))
#include <sys/types.h>
#include <netinet/in.h>
#endif

#ifdef pc
#include "lctypes.h"
#include <string.h>	
#endif

#ifdef vms
#include <in.h>
#endif


#include "asn1.h"

#ifndef NULL
#define NULL	0
#endif
#define ERROR(string)


/*
 * asn_build_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_int(data, datalength, type, intp, intsize)
    register u_char *data;	/* IN - pointer to start of output buffer */
    register int    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - asn type of object */
    register long   *intp;	/* IN - pointer to start of long integer */
    register int    intsize;    /* IN - size of *intp */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register long integer;
    register u_long mask;

    if (intsize != sizeof (long))
	return NULL;
    integer = *intp;
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this
     * 2's complement integer.  There should be no sequence of 9
     * consecutive 1's or 0's at the most significant end of the
     * integer.
     */
    mask = 0x1FF << ((8 * (sizeof(long) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */
    while((((integer & mask) == 0) || ((integer & mask) == mask))
	  && intsize > 1){
	intsize--;
	integer <<= 8;
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;
    mask = 0xFF << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while(intsize--){
	*data++ = (u_char)((integer & mask) >> (8 * (sizeof(long) - 1)));
	integer <<= 8;
    }
    return data;
}


/*
 * asn_build_unsigned_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_unsigned_int(data, datalength, type, intp, intsize)
    register u_char *data;	/* IN - pointer to start of output buffer */
    register int    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - asn type of object */
    register u_long *intp;	/* IN - pointer to start of long integer */
    register int    intsize;    /* IN - size of *intp */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register u_long integer;
    register u_long mask;
    int add_null_byte = 0;

    if (intsize != sizeof (long))
	return NULL;
    integer = *intp;
    mask = 0xFF << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    if ((u_char)((integer & mask) >> (8 * (sizeof(long) - 1))) & 0x80){
	/* if MSB is set */
	add_null_byte = 1;
	intsize++;
    }
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this 2's complement integer.
     * There should be no sequence of 9 consecutive 1's or 0's at the most significant end of the
     * integer.
     */
    mask = 0x1FF << ((8 * (sizeof(long) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */
    while((((integer & mask) == 0) || ((integer & mask) == mask)) && intsize > 1){
	intsize--;
	integer <<= 8;
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;
    if (add_null_byte == 1){
	*data++ = '\0';
	intsize--;
    }
    mask = 0xFF << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while(intsize--){
	*data++ = (u_char)((integer & mask) >> (8 * (sizeof(long) - 1)));
	integer <<= 8;
    }
    return data;
}


/*
 * asn_build_string - Builds an ASN octet string object containing the input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_string(data, datalength, type, string, strlength)
    u_char	    *data;	    /* IN - pointer to start of object */
    register int    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of string */
    u_char	    *string;	    /* IN - pointer to start of input buffer */
    register int    strlength;	    /* IN - size of input buffer */
{
/*
 * ASN.1 octet string ::= primstring | cmpdstring
 * primstring ::= 0x04 asnlength byte {byte}*
 * cmpdstring ::= 0x24 asnlength string {string}*
 * This code will never send a compound string.
 */
    data = asn_build_header(data, datalength, type, strlength);
    if (data == NULL)
	return NULL;
    if (*datalength < strlength)
	return NULL;
#ifdef pc
    memcpy((char *)data, (char *)string, strlength);
#else
    bcopy((char *)string, (char *)data, strlength);
#endif
    *datalength -= strlength;
    return data + strlength;
}


/*
 * asn_build_header - builds an ASN header for an object with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_build_header(data, datalength, type, length)
    register u_char *data;	/* IN - pointer to start of object */
    int		    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - ASN type of object */
    int		    length;	/* IN - length of object */
{
    if (*datalength < 1)
	return NULL;
    *data++ = type;
    (*datalength)--;
    return asn_build_length(data, datalength, length);
    
}

/*
 * asn_build_sequence - builds an ASN header for a sequence with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_build_sequence(data, datalength, type, length)
    register u_char *data;	/* IN - pointer to start of object */
    int		    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - ASN type of object */
    int		    length;	/* IN - length of object */
{
    *datalength -= 4;
    if (*datalength < 0){
	*datalength += 4;	/* fix up before punting */
	return NULL;
    }
    *data++ = type;
    *data++ = (u_char)(0x02 | ASN_LONG_LEN);
    *data++ = (u_char)((length >> 8) & 0xFF);
    *data++ = (u_char)(length & 0xFF);
    return data;
}

u_char *
asn_build_length(data, datalength, length)
    register u_char *data;	/* IN - pointer to start of object */
    int		    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    register int    length;	/* IN - length of object */
{
    u_char    *start_data = data;

    /* no indefinite lengths sent */
    if (length < 0x80){
	if (*datalength < 1){
	    ERROR("build_length");
	    return NULL;
	}	    
	*data++ = (u_char)length;
    } else if (length <= 0xFF){
	if (*datalength < 2){
	    ERROR("build_length");
	    return NULL;
	}	    
	*data++ = (u_char)(0x01 | ASN_LONG_LEN);
	*data++ = (u_char)length;
    } else { /* 0xFF < length <= 0xFFFF */
	if (*datalength < 3){
	    ERROR("build_length");
	    return NULL;
	}	    
	*data++ = (u_char)(0x02 | ASN_LONG_LEN);
	*data++ = (u_char)((length >> 8) & 0xFF);
	*data++ = (u_char)(length & 0xFF);
    }
    *datalength -= (data - start_data);
    return data;

}

/*
 * asn_build_objid - Builds an ASN object identifier object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_objid(data, datalength, type, objid, objidlength)
    register u_char *data;	    /* IN - pointer to start of object */
    int		    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of object */
    oid		    *objid;	    /* IN - pointer to start of input buffer */
    int		    objidlength;    /* IN - number of sub-id's in objid */
{
/*
 * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
    u_char buf[MAX_OID_LEN];
    register u_char *bp = buf;
    register oid *op = objid;
    int    asnlength;
    register u_long subid, mask, testmask;
    register int bits, testbits;

    if (objidlength < 2){
	*bp++ = 0;
	objidlength = 0;
    } else {
	*bp++ = op[1] + (op[0] * 40);
	objidlength -= 2;
	op += 2;
    }

    while(objidlength-- > 0){
	subid = *op++;
	if (subid < 127){ /* off by one? */
	    *bp++ = subid;
	} else {
	    mask = 0x7F; /* handle subid == 0 case */
	    bits = 0;
	    /* testmask *MUST* !!!! be of an unsigned type */
	    for(testmask = 0x7F, testbits = 0; testmask != 0;
		testmask <<= 7, testbits += 7){
		if (subid & testmask){	/* if any bits set */
		    mask = testmask;
		    bits = testbits;
		}
	    }
	    /* mask can't be zero here */
	    for(;mask != 0x7F; mask >>= 7, bits -= 7){
		/* fix a mask that got truncated above */
		if (mask == 0x1E00000)  
		    mask = 0xFE00000;
		*bp++ = (u_char)(((subid & mask) >> bits) | ASN_BIT8);
	    }
	    *bp++ = (u_char)(subid & mask);
	}
    }
    asnlength = bp - buf;
    data = asn_build_header(data, datalength, type, asnlength);
    if (data == NULL)
	return NULL;
    if (*datalength < asnlength)
	return NULL;
#ifdef pc
    memcpy((char *)data, (char *)buf, asnlength);
#else
    bcopy((char *)buf, (char *)data, asnlength);
#endif
    *datalength -= asnlength;
    return data + asnlength;
}

/*
 * asn_build_null - Builds an ASN null object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_null(data, datalength, type)
    u_char	    *data;	    /* IN - pointer to start of object */
    int		    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of object */
{
/*
 * ASN.1 null ::= 0x05 0x00
 */
    return asn_build_header(data, datalength, type, 0);
}

/*
 * asn_build_bitstring - Builds an ASN bit string object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_bitstring(data, datalength, type, string, strlength)
    u_char	    *data;	    /* IN - pointer to start of object */
    register int    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of string */
    u_char	    *string;	    /* IN - pointer to start of input buffer */
    register int    strlength;	    /* IN - size of input buffer */
{
/*
 * ASN.1 bit string ::= 0x03 asnlength unused {byte}*
 */
    if (strlength < 1 || *string < 0 || *string > 7){
	ERROR("Building invalid bitstring");
	return NULL;
    }
    data = asn_build_header(data, datalength, type, strlength);
    if (data == NULL)
	return NULL;
    if (*datalength < strlength)
	return NULL;
#ifdef pc
    memcpy((char *)data, (char *)string, strlength);
#else
    bcopy((char *)string, (char *)data, strlength);
#endif
    *datalength -= strlength;
    return data + strlength;
}


/*
 * asn_build_unsigned_int64 - builds an ASN object containing a 64 bit integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_unsigned_int64(data, datalength, type, cp, countersize)
    register u_char *data;	/* IN - pointer to start of output buffer */
    register int    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - asn type of object */
    struct counter64 *cp;	/* IN - pointer to counter struct */
    register int    countersize; /* IN - size of *intp */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register u_long low, high;
    register u_long mask, mask2;
    int add_null_byte = 0;
    int intsize;

    if (countersize != sizeof (struct counter64))
	return NULL;
    intsize = 8;
    low = cp->low;
    high = cp->high;
    mask = 0xFF << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    if ((u_char)((high & mask) >> (8 * (sizeof(long) - 1))) & 0x80){
	/* if MSB is set */
	add_null_byte = 1;
	intsize++;
    }
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this 2's
     * complement integer.
     * There should be no sequence of 9 consecutive 1's or 0's at the most
     * significant end of the integer.
     */
    mask2 = 0x1FF << ((8 * (sizeof(long) - 1)) - 1);
    /* mask2 is 0xFF800000 on a big-endian machine */
    while((((high & mask2) == 0) || ((high & mask2) == mask2))
	  && intsize > 1){
	intsize--;
	high = (high << 8)
	    | ((low & mask) >> (8 * (sizeof(long) - 1)));
	low <<= 8;
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;
    if (add_null_byte == 1){
	*data++ = '\0';
	intsize--;
    }
    while(intsize--){
	*data++ = (u_char)((high & mask) >> (8 * (sizeof(long) - 1)));
	high = (high << 8)
	    | ((low & mask) >> (8 * (sizeof(long) - 1)));
	low <<= 8;
	
    }
    return data;
}
