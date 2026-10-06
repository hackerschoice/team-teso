#ifndef _lcnmib_h_
#define _lcnmib_h_
   
#include "asn1.h"
   
int32 MibWriteControl( void );
int32 MibVarBind( void );

uint32 BoundAlphaSyntax( oid *, int );
uint32 EnumSyntax( oid *, int );
uint32 Integer( oid *, int );
uint32 IpAddress( oid *, int );
uint32 OctetString( oid *, int );
uint32 TimeTicks( oid *, int );
uint32 WriteAccess( oid *, int );
        
#endif /*_lcnmib_h_*/















































