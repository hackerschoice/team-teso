/************************************************************************
 *                                                                      
 *              Copyright 1997 by Bay Networks Inc                      
 *                                                                      
 *  PROPRIETARY RIGHTS of Bay Networks Inc are involved in the          
 *  subject matter of this material.  All manufacturing, reproduction,  
 *  use, and sales rights pertaining to this subject matter are         
 *  governed by the license agreement.  The buyer or recipient of this  
 *  package, implicitly accepts the terms of the license.               
 *                                                                      
 ************************************************************************/

/******************************************************************************
 *                                                                            
 * FILE NAME AND DESCRIPTION                                                  
 *                                                                            
 *       lcnmib.c - convert SNMP portions of ascii config file to MCNS DHCP/TFTP format	      
 *                                                                           
 * REVISION HISTORY                                                          
 *                                                                           
 * DATE        AUTHOR REASON FOR CHANGE                                       
 *                                                                            
 * 6/20/97     jb     Derived from LANcity version of lcconfig.c.                                                                           
 *	                                                                           
 *  DESCRIPTION OF ALGORITHM                                                  
 *                                                                            
 *  ROUTINES IN THIS FILE:                                                    
 *                                                                            
 *  NOTES / RESTRICTIONS:                                                     
 ******************************************************************************
*/


/*
 ******************************************************************************
 *
 * LIST OF INCLUDE FILES FOLLOWS
 *
 ******************************************************************************
*/

#ifndef UNIX_LCN
#include <windows.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#ifdef UNIX_LCN
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif 
  
/*
 ******************************************************************************
 *
 * DEFINES FOLLOW
 *
 ******************************************************************************
*/

#include "lctypes.h"
#include "confdefs.h"
#include "confdata.h"
#include "lcnmib.h"
#include "lcconfig.h"
#include "snmpimpl.h"

#ifdef KINETICS
#include "gw.h"
#endif

/*
//#if (defined(unix) && !defined(KINETICS))
//#include <sys/types.h>
//#include <netinet/in.h>
//#endif
*/

#ifdef pc
/*//#include <winsock.h>*/
#include <sys/types.h>
#include <string.h>	
#endif

#ifdef vms
#include <in.h>
#endif

static uint32 GetOnOffMibVar( oid * Oid, int OidLength );
static uint32 GetPassBlockMibVar( oid * Oid, int OidLength );
static uint32 GetValidInvalidMibVar( oid * Oid, int OidLength );
static uint32 GetInterfaceMibVar( oid * Oid, int OidLength );
static uint32 GetResetMibVar( oid * Oid, int OidLength );
static uint32 GetSecGrpTypeMibVar( oid * Oid, int OidLength );
static uint32 GetStartEndProtoMibVar( oid * Oid, int OidLength );
static uint32 GetPortFiltTypeMibVar( oid * Oid, int OidLength );
static uint32 GetETypeValueMibVar( oid * Oid, int OidLength );

typedef enum { SymbolicTag, LiteralOidTag } TAG_TYPE;

static char * pTrailingIndicies;
static TAG_TYPE SaveIndicies(char *);
static int AppendIndicies(oid *, int);
            
#define MAX_OID_NODES 50

static CombinedOid[MAX_OID_NODES];

typedef enum { WriteAccessItemType, MibObjectItemType } ITEM_TYPE;
                       
typedef struct mib_struct {
  char * label;
  uint32 (* extractor) (oid *, int);
  int IndiciesRequired;
  oid Oid[MAX_OID_NODES];
} mib_struct_t;

static mib_struct_t DummyMibStruct = { NULL, NULL, -1, 0 };

static mib_struct_t MibStruct[] =          
{	                                       
 
  {"lcLcpAddrFiltControl", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,27,1},
  {"lcLcpAddrFiltSendDu", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,27,2},
  {"lcLcpAddrActionOnNoMatch", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,27,3},
  
  {"lcLcpIpAdrFiltStatus", GetValidInvalidMibVar, 1, 1,3,6,1,4,1,482,50,2,27,4,1,2},
  {"lcLcpIpAdrFiltInterface", GetInterfaceMibVar, 1, 1,3,6,1,4,1,482,50,2,27,4,1,3},
  {"lcLcpAddr1orDa", IpAddress, 1, 1,3,6,1,4,1,482,50,2,27,4,1,4},
  {"lcLcpAddr1orDaMask", IpAddress, 1, 1,3,6,1,4,1,482,50,2,27,4,1,5},
  {"lcLcpAddr1orSa", IpAddress, 1, 1,3,6,1,4,1,482,50,2,27,4,1,6},
  {"lcLcpAddr1orSaMask", IpAddress, 1, 1,3,6,1,4,1,482,50,2,27,4,1,7},
  {"lcLcpAdrFiltAction", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,27,4,1,8},
  {"lcLcpAdrFiltMatchResetCount", GetResetMibVar, 1, 1,3,6,1,4,1,482,50,2,27,4,1,10},
  
  {"lcLcpProtoFiltControl", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,28,1},
  {"lcLcpProtoFiltSendDu", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,28,2},
  {"lcLcpProtoActionOnNoMatch", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,28,3},
  
  {"lcLcpIpProtoFiltStatus", GetValidInvalidMibVar, 1, 1,3,6,1,4,1,482,50,2,28,4,1,2},
  {"lcLcpStartProto", GetStartEndProtoMibVar, 1, 1,3,6,1,4,1,482,50,2,28,4,1,3},
  {"lcLcpEndProto", GetStartEndProtoMibVar, 1, 1,3,6,1,4,1,482,50,2,28,4,1,4},
  {"lcLcpProtoFilterAction", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,28,4,1,5},
  {"lcLcpProtoMatchResetCount", GetResetMibVar, 1, 1,3,6,1,4,1,482,50,2,28,4,1,7},
  
  {"lcLcpPortFiltControl", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,29,1},
  {"lcLcpPortFiltSendDu", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,29,2},
  {"lcLcpPortActionOnNoMatch", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,29,3},
  
  {"lcLcpIpPortFiltStatus", GetValidInvalidMibVar, 1, 1,3,6,1,4,1,482,50,2,29,4,1,2},
  {"lcLcpStartPort", Integer, 1, 1,3,6,1,4,1,482,50,2,29,4,1,3},
  {"lcLcpEndPort", Integer, 1, 1,3,6,1,4,1,482,50,2,29,4,1,4},
  {"lcLcpPortFilterAction", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,29,4,1,5},
  {"lcLcpPortMatchResetCount", GetResetMibVar, 1, 1,3,6,1,4,1,482,50,2,29,4,1,7},
  {"lcLcpPortFiltInterface", GetInterfaceMibVar, 1, 1,3,6,1,4,1,482,50,2,29,4,1,8},
  {"lcLcpPortFiltType", GetPortFiltTypeMibVar, 1, 1,3,6,1,4,1,482,50,2,29,4,1,9},
  
  {"lcLcpOptionFiltControl", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,30,1},
  {"lcLcpOptionFiltResetCount", GetResetMibVar, 1, 1,3,6,1,4,1,482,50,2,30,3},
  {"lcLcpOptionFiltSendDu", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,30,4},

  {"lcLcpIGMPReportFiltControl", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,32,1},
  {"lcLcpIGMPFiltResetCount", GetResetMibVar, 1, 1,3,6,1,4,1,482,50,2,32,3},
  {"lcLcpIGMPFiltSendDu", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,32,4},
  {"lcLcpIGMPFiltTrap", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,32,5},
  
  {"lcLcpEtypeFiltControl", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,31,1},
  {"lcLcpEtypeFiltIpOnly", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,31,2},
  {"lcLcpEtypeFiltNovell", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,31,3},
  {"lcLcpEtypeActionOnNoMatch", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,31,4},

  {"lcLcpEtypeFiltStatus", GetValidInvalidMibVar, 1, 1,3,6,1,4,1,482,50,2,31,5,1,2},
  {"lcLcpEtypeFiltType", GetETypeValueMibVar, 1, 1,3,6,1,4,1,482,50,2,31,5,1,3},
  {"lcLcpEtypeFiltValue", OctetString, 1, 1,3,6,1,4,1,482,50,2,31,5,1,4},
  {"lcLcpEtypeFilterAction", GetPassBlockMibVar, 1, 1,3,6,1,4,1,482,50,2,31,5,1,5},
  {"lcLcpEtypeMatchResetCount", GetResetMibVar, 1, 1,3,6,1,4,1,482,50,2,31,5,1,7},
  
  {"lcLcpSecGroupFilter", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,9,1},
  {"lcLcpSecGrpType", GetSecGrpTypeMibVar, 1, 1,3,6,1,4,1,482,50,2,9,3},
  {"lcLcpSecurityGrp", OctetString, 1, 1,3,6,1,4,1,482,50,2,9,4},
  {"lcLcpBcastFilter", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,9,13},
  {"lcLcpMcastFilter", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,9,14},
  {"lcLcpSecGrpSpanTree", GetOnOffMibVar, 1, 1,3,6,1,4,1,482,50,2,9,15},
  {NULL}
};

static oid DummyOid = 0;

static int32 ExtractArguments(ITEM_TYPE ItemType, mib_struct_t * currentEntry)
{
  int32 extractResult;
  int OidLength;

  /*append any required indicies to the oid*/
  OidLength = AppendIndicies(currentEntry->Oid, currentEntry->IndiciesRequired);
  if ( OidLength == 0)
  {
    printf("Bad oid length\n");
    return nok;
  }
  /* execute the extract routine */
  if (ItemType == WriteAccessItemType)
    extractResult = WriteAccess(CombinedOid, OidLength);
  else
  {
    extractResult = currentEntry->extractor(CombinedOid, OidLength);
  }
#if 0
  /* clear comment string */
  if (0 == fgets(line_buffer, 256, input))
  {
    return (nok);
  }
#endif	
  if (extractResult == ok) 
  {
    return ok;
  }
  sprintf (errParaString, " %s", label_string);
  reperror(badParameterErr, ifilename, errParaString);
  return (nok);
}

static int32 get_item(ITEM_TYPE ItemType)
{
  uint32 	matchResult, extractResult;
  int8 *overall_length_ptr;
  mib_struct_t * currentEntry;

  /* read in the next label and decode it */
  iresult = fscanf(input, "%s", label_string);
  
  if (iresult == EOF || iresult == 0)
  {
    reperror(badLabelErr, ifilename, label_string);
    return (nok);
  }
                            
  /* now write out the code and reserve byte for 
     the overall length of the combined sub-TLVs */ 

  *out_buffer_ptr++ = snmp_mib_code;
  overall_length_ptr = out_buffer_ptr++; 

  matchResult = notMatched;

  if (LiteralOidTag == SaveIndicies(label_string))
    return ExtractArguments(ItemType, &DummyMibStruct);

  for (currentEntry = MibStruct; currentEntry->label != NULL; currentEntry++)
  {                
    if (strcmp (label_string, currentEntry->label) != 0)
      continue;
    /* have matched the label */
    matchResult = matched;
    break;
  }

  if (matchResult != matched)
  {
    reperror(badLabelErr, ifilename, label_string);
    return (nok);
  }
  if ( ok != ExtractArguments(ItemType, currentEntry))
  {
    sprintf (errParaString, " %s", label_string);
    reperror(badParameterErr, ifilename, errParaString);
    return (nok);
  }

  /* update the byte previously reserved for 
     the overall length of the combined sub-TLVs */ 

  *overall_length_ptr = (unsigned int)out_buffer_ptr - (unsigned int)overall_length_ptr - 1; 
  
  return (ok);
}

int32 MibVarBind( void )
{
  int32 temp = get_item(MibObjectItemType);
  return temp;
}

int32 MibWriteControl( void )
{
  return get_item(WriteAccessItemType);
}

uint32 BoundAlphaSyntax( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  listlength = sizeof out_buffer - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, 
				     &OidLength, STRING, strlen(inString), 
				     inString, &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 EnumSyntax( oid * Oid, int OidLength )
{
  int16  opres;
  int inInteger;
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */

  opres = fscanf(input, "%d", &inInteger);
  
  if (opres == EOF || opres == 0)
    return (nok);

  /* perform range checks here */

  listlength = sizeof out_buffer - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, 
				     &OidLength, INTEGER, sizeof inInteger, 
				     &inInteger, &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}     

uint32 Integer( oid * Oid, int OidLength )
{
  int16  opres;
  int inInteger;
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */


  opres = fscanf(input, "%d", &inInteger);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 IpAddress( oid * Oid, int OidLength )
{
  int16  opres;
  int inAddr1, inAddr2, inAddr3, inAddr4;
  int8 inIPAddress[4];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */

  opres = fscanf(input, "%d.%d.%d.%d", &inAddr1, &inAddr2, &inAddr3, &inAddr4);

  if (opres == EOF || opres == 0)
    return (nok);
                                      
  inIPAddress[0] = (int8) inAddr1;                                      
  inIPAddress[1] = (int8) inAddr2;                                      
  inIPAddress[2] = (int8) inAddr3;                                      
  inIPAddress[3] = (int8) inAddr4;                                      

  /* perform range checks here */

  listlength = sizeof out_buffer - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     IPADDRESS, sizeof inIPAddress, 
				     inIPAddress, &listlength);

  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 OctetString( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0)
    return (nok);

  /* perform range checks here */

  listlength = sizeof out_buffer - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength,
				     STRING, strlen(inString), inString, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 TimeTicks( oid * Oid, int OidLength )
{
  int16  opres;
  int inInteger;
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */

  opres = fscanf(input, "%d", &inInteger);

  if (opres == EOF || opres == 0) 
    return (nok);

  /* perform range checks here */

  listlength = sizeof out_buffer - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     TIMETICKS, sizeof inInteger, &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL)
    return (nok);

  return (ok);
}

static TAG_TYPE SaveIndicies(char * s)
{
  if ( 0 != atoi(s))
  {
    pTrailingIndicies = s;
    return LiteralOidTag;
  }
  pTrailingIndicies = strchr (s, '.');
  if (pTrailingIndicies == NULL)
    return;
  *pTrailingIndicies++ = 0x00;
  return SymbolicTag;
}

static int AppendIndicies( oid * BaseOid, int IndiciesRequired )
{
  int n, baseIndicies;
  char * p;
  long nLong;

  for (n = 0; BaseOid[n] != 0; ++n)
    CombinedOid[n] = BaseOid[n];	

  baseIndicies = n;

  if ( pTrailingIndicies == NULL )
    return n;

  for ( p = pTrailingIndicies; *p != 0x00; ++p)
  {
    nLong = strtol(p, &p, 10);
#if 0
    if (nLong == 0)
      return 0;
#endif
    CombinedOid[n++] = (oid) nLong;
    
    if (*p == '.')
      continue;
    if (*p == 0x00)
      break;
    return 0;
  }
  if (IndiciesRequired == -1)
    return n;

  if ( (n - baseIndicies) != IndiciesRequired )
    return 0; 
  return n;
}

uint32 WriteAccess( oid * Oid, int OidLength )
{
  int16  opres;
  int inInteger;
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */

  listlength = sizeof out_buffer - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = asn_build_objid(out_buffer_ptr, &listlength,
				   (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID), 
				   Oid, OidLength);
  if (out_buffer_ptr == NULL)
    return (nok);

  opres = fscanf(input, "%d", &inInteger);

  if (opres == EOF || opres == 0) 
    return (nok);

  *out_buffer_ptr++ = (uint8 *) inInteger;
  
  return ok;
}


uint32 GetOnOffMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "on") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "bcastFilteringOn") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "mcastFilteringOn") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "secGrpSpanTreeOn") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "off") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "bcastFilteringOff") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "mcastFilteringOff") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "secGrpSpanTreeOff") == 0)
  {
    inInteger = 2;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1 or a 2
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 2)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 GetPassBlockMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "pass") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "block") == 0)
  {
    inInteger = 2;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1 or a 2
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 2)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 GetValidInvalidMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "valid") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "invalid") == 0)
  {
    inInteger = 2;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1 or a 2
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 2)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 GetInterfaceMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "fromEnet") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "fromCatv") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "fromEither") == 0)
  {
    inInteger = 3;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1, 2, or a 3
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 3)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}



uint32 GetResetMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "reset") == 0)
  {
    inInteger = 1;
  }
  
  inInteger = 1;


  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 GetPortFiltTypeMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "sourcePort") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "destinationPort") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "eitherPort") == 0)
  {
    inInteger = 3;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1, 2, or a 3
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 3)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}



uint32 GetStartEndProtoMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "icmp") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "igmp") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "st") == 0)
  {
    inInteger = 5;
  }
  else if (strcmp (inString, "tcp") == 0)
  {
    inInteger = 6;
  }
  else if (strcmp (inString, "egp") == 0)
  {
    inInteger = 8;
  }
  else if (strcmp (inString, "igp") == 0)
  {
    inInteger = 11;
  }
  else if (strcmp (inString, "udp") == 0)
  {
    inInteger = 17;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1, 2, or a 3
     */
    inInteger = atoi(inString);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

uint32 GetETypeValueMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "ethertype") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "dsap") == 0)
  {
    inInteger = 2;
  }
  else if (strcmp (inString, "ssap") == 0)
  {
    inInteger = 3;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1, 2, or a 3
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 3)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}


uint32 GetSecGrpTypeMibVar( oid * Oid, int OidLength )
{
  int16  opres;
  int8 inString[max_string_length];
  int listlength;   /* IN/OUT - number of valid bytes left in output buffer */
  int inInteger;

  opres = fscanf(input, "%s", inString);

  if (opres == EOF || opres == 0) return (nok);

  /* perform range checks here */
  
  if (strcmp (inString, "simple") == 0)
  {
    inInteger = 1;
  }
  else if (strcmp (inString, "shared") == 0)
  {
    inInteger = 2;
  }
  else
  {
    /* convert string to integer an make sure
     * either a 1 or a 2
     */
    inInteger = atoi(inString);
    if ((inInteger < 1) || (inInteger > 2)) 
      return (nok);
  }

  listlength = sizeof (out_buffer) - (out_buffer_ptr - out_buffer);
  out_buffer_ptr = snmp_build_var_op(out_buffer_ptr, Oid, &OidLength, 
				     INTEGER, sizeof inInteger,  &inInteger, 
				     &listlength);
  if (out_buffer_ptr == NULL) 
    return (nok);

  return (ok);
}

