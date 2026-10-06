/*
 ******************************************************************************
 *                                                                            *
 *      	Copyright 1994 by Applitek / LANcity Corporation              *
 *                                                                            *
 *  PROPRIETARY RIGHTS of LANcity Corp are involved in the                   *
 *  subject matter of this material.  All manufacturing, reproduction,        *
 *  use, and sales rights pertaining to this subject matter are               *
 *  governed by the license agreement.  The buyer or recipient of this        *
 *  package, implicitly accepts the terms of the license.                     *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************
 *                                                                            *
 * FILE NAME AND DESCRIPTION                                                  *
 *                                                                            *
 *       lcconfig.c - convert ascii config file to bootp format	      *
 *                                                                            *
 * REVISION HISTORY                                                           *
 *                                                                            *
 * DATE        AUTHOR REASON FOR CHANGE                                       *
 *                                                                            *
 *                                                                            *
 *	12/14/94	 gw	initial version
 *	01/05/95	 gw	move to gcc to allow ANSI C
 *	03/28/95	 gw	move to Msoft Visual C++ PC
 *	04/10/95	 gw rework for integration with Access RDBMS 
 *  06/08/95	 gw add snmp security based on manager IP and MAC address 
 *  06/12/95	 gw add max nodes on broadband   
 *  06/12/95	 gw add default gateway  
 *  10/06/95	 gw add snmp community strings         
 *  10/18/95	 gw fix problem with freqs of xx.50 in get_freq                
 *  01/10/96	 gw add support for multiple managers + b/w limits            
 *  02/08/96	 gw add support for 750Mhz LCP       
 *	04/09/96	 gw	add LCw support
 *  04/09/96	 gw	add encryption support
 *  07/22/96	 gw add 3.0 support -client ip addresses + s/w upgrade
 *  08/008/96	 gw port to unix
 *                                                                            *
 *  DESCRIPTION OF ALGORITHM                                                  *
 *                                                                            *
 *  ROUTINES IN THIS FILE:                                                    *
 *                                                                            *
 *  NOTES / RESTRICTIONS:                                                     *
 ******************************************************************************
*/


/*
 ******************************************************************************
 *                                                                            *
 * LIST OF INCLUDE FILES FOLLOWS
 *                                                                            *
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
 *                                                                            *
 * DEFINES FOLLOW
 *                                                                            *
 ******************************************************************************
*/

#include "lctypes.h"
#include "confdefs.h"
#include "confdata.h"
#include "lcnmib.h"

/*
 ******************************************************************************
 *                                                                            *
 * SCCS_ID STRING FOLLOWS
 *                                                                            *
 ******************************************************************************
*/



/************************************************************************/
/*									*/
/*		       	         					*/
/* Usage		  						*/
/*									*/
/*									*/	
/*									*/	
/* Notes								*/
/*	the infile is the ascii config file		 		*/
/*	the outfile is BOOTP format config file				*/
/*	the keyfile contains the selected authorization key data      	*/
/*									*/
/*									*/
/************************************************************************/



/* external routines */
#ifndef UNIX_LCN
extern uint32	htonl(uint32);   
extern uint32	inet_addr(uint8 *); 
#endif

extern void reperror(char *, char *, char *);

/* other externals */

extern char	errHeader[];

extern char	infileOpenErr[];
extern char	outfileOpenErr[];
extern char	keyfileOpenErr[];
extern char	badLabelErr[];
extern char	keyMatchErr[];
extern char	infileCloseErr[];
extern char	outfileCloseErr[];
extern char	keyfileCloseErr[];
extern char	badFreqErr[];
extern char	badYesNoErr[];
extern char	badLoopDelayErr[];
extern char	badKeyLengthErr[];
extern char	badMaxNodesErr[]; 
extern char	badMaxCDMsErr[]; 
extern char	dataRateErr[];
extern char	accessTypeErr[];
extern char	badMinContentionErr[];
extern char	badMaxConcatErr[]; 
extern char badParameterErr[];



/* forward declarations */
int32	get_freq(uint8, uint32, uint32);
int32	get_yes_no(uint8, uint32, uint32);
int32	get_ip_addr(uint8, uint32, uint32);  
int32	get_mgr_mac_addr(uint8, uint32, uint32);
int32	get_max_ld(uint8, uint32, uint32); 
int32	get_changed_key(uint8, uint32, uint32); 
int32	get_key_id(uint8, uint32, uint32);
int32	get_max_nodes(uint8, uint32, uint32); 
int32	get_max_cdms(uint8, uint32, uint32);        
int32	get_min_contention(uint8, uint32, uint32);    
int32	get_community_string(uint8, uint32, uint32);  
int32	get_max_concat(uint8, uint32, uint32);
int32	get_access_type(uint8, uint32, uint32); 
int32	get_max_rate(uint8, uint32, uint32);  
int32	get_mgr_ip_addr_string(uint8, uint32, uint32);  
int32	getEnetClientMacAddr(uint8, uint32, uint32);
int32	getClientIpAddrString(uint8, uint32, uint32);
int32	get_encrypted_nets(uint8, uint32, uint32);
int32	getDecimalNumber(uint8, uint32, uint32);   
int32	getString(uint8, uint32, uint32);
int32	comment_line(uint8, uint32, uint32);

int16 	extractIpFromInputStream(uint8 *);   
int16 	extractMacFromInputStream(uint8 *);
/* 
uint32	htonl(uint32); 
*/
uint16	streamToHexAsc(uint8 *, uint8 *, uint16);  

extern int32 get_mib(uint8, uint32, uint32);



void xor_keys(uint8 *, uint8 *, uint8 *);
void MD5digest (uint8 *, uint16, uint8 *);

int8	errParaString[64];

FILE	*input;
FILE	*output;
FILE	*keyfile;

uint8	ifilename[64];
uint8	ofilename[64];
uint8	keyfilename[64];

int16	iresult, oresult;
int8	label_string[32];


/* decode table for label value tuples */

typedef struct
{
  int8		label[32];
  int32		(*extractor)(uint8 , uint32 , uint32);
  uint32	minimum;
  uint32      	maximum;
  uint8		code;
} decode_entry;



#define decodeTableLength	37

	
decode_entry	decodeTable[decodeTableLength] = {
  "//", (comment_line), 0, 0, 0,
  "TxFrequency", (get_freq), 8000, 100000, tx_frequency_code,
  "RxFrequency", (get_freq), 55000, 750000, rx_frequency_code,
  "ReferenceNode", (get_yes_no), 0, 0, reference_node_code,
  "JoinNetwork", (get_yes_no), 0, 0, join_net_code,
  "MaxLoopDel", (get_max_ld), 96, 1600, max_ld_code,
  "SNMPReadOnly", (get_yes_no), 0, 0, net_mgmt_access_mode_code,
  "FreqScan", (get_yes_no), 0, 0, freq_scan_code,
  "AutoInstall", (get_yes_no), 0, 0, auto_install_code,
  "MaxNodes", (get_max_nodes), 1, 16, max_nodes_code,
  "KeyChange", (get_changed_key), 0,0, change_key_code, 
  "KeyId", (get_key_id), 0,0, key_id_code,
  "MaxCDMs", (get_max_cdms), 0,0, maxcdm_code,
  "ManagerIpAddr", (get_mgr_ip_addr_string), 0, 0, mgr_ip_addr_code,
  "DefaultGateway", (get_ip_addr), 0, 0, default_gw_code,
  "ReadComm", (get_community_string), 0, 0, read_comm_code,  
  "WriteComm", (get_community_string), 0, 0, write_comm_code,
  "TrapComm", (get_community_string), 0, 0, trap_comm_code,
  "MaxConcat", (get_max_concat), 0, 4, max_concat_code,
  "AccessType", (get_access_type), 1, 3, access_type_code, 
  "ForwardMax", (get_max_rate), 0, 0, fwd_max_code,
  "ReturnMax", (get_max_rate), 0, 0, ret_max_code,
  "minContention", (get_min_contention), 10, 95, min_cont_code,
  "ManagerEnetAddr", (get_mgr_mac_addr), 0, 0, mgr_mac_addr_code,
  "ClientEnetAddr", (getEnetClientMacAddr), 0, 0, client_mac_addr_code,
  "ClientIpAddr", (getClientIpAddrString), 0, 0, client_ip_addr_code,
  "swRevision", (getDecimalNumber), 0, 0, sw_rev_code,
  "upgradeFile", (getString), 0, 0, upgrade_file_code,
  "TFTPServIpAddr", (get_ip_addr), 0, 0, tftp_server_ip_addr_code,
  "Encrypt", (get_yes_no), 0, 0, encrypt_code,
  "OffNetGateway", (get_yes_no), 0, 0, off_net_gateway_code,
  "KeyServer", (get_ip_addr), 0, 0, key_server_code,
  "EncryptedNets", (get_encrypted_nets), 0, 0, encrypted_net_code,
  "SnmpVariable", (get_mib), 0, 0, snmp_mib_code,
  "LcnLessEnabled", (get_yes_no), 0, 0, lcnless_enabled_code,
  "ClientEnetAddr16", (getEnetClientMacAddr), 0, 0, client_mac_addr_code_16,
  "ClientIpAddr16", (getClientIpAddrString), 0, 0, client_ip_addr_code_16,
};



/* comparison strings */

int8	yes_string[] = "yes";
int8	no_string[] = "no";

uint8	yes_no_buffer[4];


uint8	line_buffer[256];
uint8	out_buffer[0x50000];
uint8	*out_buffer_ptr; 

uint8	hexasc_buffer[0x50000]; 
uint16	binary_len;
uint8   hexasc[] = {
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,
        0x38,
        0x39,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46
        };
 

uint16	buff_len;
uint8	digest[16];
uint8	digest_input_buffer[0x50000];

uint8	inputFile[64];

uint8	xor_result[key_length];      


/*testing */
uint8	encryptedNets[maxEncryptedNets+1][4];

int16 build_config_file (uint8 *inFile, uint8 *outFile,
				uint8 *keyFile)


{
  uint32 	matchResult, extractResult;
  uint32	i;
  int8	*buff_ptr; 
  uint16	numread;
                          

  /* save a global copy of the file names for use during error processing */
  strcpy(ifilename, inFile);
  strcpy(ofilename, outFile);
  strcpy(keyfilename, keyFile);
 

  if ((input = fopen(inFile, "r")) == NULL)
  {
    reperror(infileOpenErr, ifilename, "");
    return (nok);
  }

  /* open output file for writing */

  if ((output = fopen(outFile, "w")) == NULL)
  {
    reperror(outfileOpenErr, ofilename, "");
    return (nok);
  }


  /* open key file for reading */

  if ((keyfile = fopen(keyFile, "r")) == NULL)
  {
    reperror(keyfileOpenErr, keyfilename, "");
    return (nok);
  }

  /* read the key data into memory from the key file */
  numread = fread( digest_input_buffer, sizeof( uint8 ), key_length, keyfile );

  /* add checks for key size ok  */


  /* set the out put pointer to the start of the output buffer */
  out_buffer_ptr = out_buffer;

  /* read in the next label and decode it until end of file reached */

  while ((iresult = fscanf(input, "%s", label_string)) != EOF)
  {
    matchResult = notMatched;
    for (i=0; i< decodeTableLength; i++)
    {
      if (strcmp (label_string, decodeTable[i].label) == 0)
      {
	/* have matched the label */
	/* execute the extract routine */
	extractResult =
	  decodeTable[i].extractor(decodeTable[i].code,
				   decodeTable[i].minimum,
				   decodeTable[i].maximum);
	if (extractResult != ok)
	{
	  sprintf (errParaString, " %s", label_string);
	  reperror(badParameterErr, ifilename, errParaString);
	  return (nok);
	}
	matchResult = matched;
	/* clear comment string */
	buff_ptr = fgets(line_buffer, 256, input);

	if (buff_ptr == 0) 
	  return (nok);
	break;
      }
    }

    if (matchResult != matched)
    {
      reperror(badLabelErr, ifilename, label_string);
      return (nok);
    }
  }

  /* get the MD5 digest of the buffer */
  
  buff_len = (uint16)(out_buffer_ptr - out_buffer);

  /* copy the outbuffer data into the digest buffer for calculation */
  memcpy(&digest_input_buffer[key_length], out_buffer, buff_len);

  /* add key length to data length for digest calculation */
  MD5digest (digest_input_buffer, (buff_len+key_length), digest);

  /* insert the digest into the out put buffer */

  *out_buffer_ptr++ = digest_code;
  *out_buffer_ptr++ = 16;
  memcpy (out_buffer_ptr, digest, 16);
  out_buffer_ptr+=16;

  /* put the end code into the buffer */

  *out_buffer_ptr++ = end_code;

  /* work around for Newt TFTP bug             
     tftp server inserts 0xd in front of any 0xa in the file -EVEN IN OCTET MODE!!!!
     encode the binary data into a hexasc representation to avoid this */

  binary_len = (uint16)(out_buffer_ptr - out_buffer);
  buff_len = streamToHexAsc(out_buffer, hexasc_buffer, binary_len);

  /* write out the bootp format file */
  oresult = fwrite(hexasc_buffer, 1, buff_len, output);

  /* close the files and clean up */
  if ((oresult = fclose(input)) < 0)
  {
    reperror(infileCloseErr, ifilename, "");
    return (nok);
  }

  if ((oresult = fclose(output)) < 0)
  {
    reperror(outfileCloseErr, ofilename, "");
    return (nok);
  }

  if ((oresult = fclose(keyfile)) < 0)
  {
    reperror(keyfileCloseErr, keyfilename, "");
    return (nok);
  }

  return(ok);

}


int32	get_freq(uint8 code, uint32 min, uint32 max)

{
  int16 opres;
  int frequency_int, frequency_dec;
  uint32 frequency_khz, net_frequency_khz;
  uint8	decimal_point;

  opres = fscanf(input, "%d", &frequency_int); 
  
  if ((opres == EOF) || (opres == 0)) 
  {
    return (nok);
  }  
    
  opres = fscanf(input, "%c", &decimal_point);
  if ((opres == EOF) || (opres == 0)) 
  {
    return (nok);
  }

  /* check for anything after the decimal point
     -access will not put it in if it is .00 */

  if (decimal_point == 0x2e)
  {	   
    opres = fscanf(input, "%d", &frequency_dec); 
    
    if ((opres == EOF) || (opres == 0)) 
    {
      return (nok);
    }
    
    /* convert the decimal part into kHz */	
    switch (frequency_dec) 
    {
    case 25:
      frequency_dec= 250;
      break;
      
      /* account for dropping trailing 0 after decimal point */	
    case 5:
      frequency_dec= 500;
      break;
      
    case 75:
      frequency_dec= 750;
      break;
    	
    default:
      sprintf (errParaString, " must be multiple of 250kHz");
      reperror(badFreqErr, ifilename, errParaString);
      return (nok);
      break;
    }				
  }
  else
  {
    frequency_dec = 0;
  }
    
  /* convert to khz for LCB */
  frequency_khz = frequency_int;
  frequency_khz *=1000;   /* multiply in 32 bit domain */
  frequency_khz = frequency_khz + (frequency_dec);

  /* perform range checks here */
  if ((frequency_khz > max) || (frequency_khz < min))
  {
    sprintf (errParaString, " %dkHz", frequency_khz);
    reperror(badFreqErr, ifilename, errParaString);
    return (nok);
  }

  /* now write out the code: length: value group to the output buffer */ 
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4; 
  net_frequency_khz = htonl(frequency_khz);
  memcpy (out_buffer_ptr, &net_frequency_khz, 4);
  out_buffer_ptr+=4;
  
  return (ok);
}	



int32	get_yes_no(uint8 code, uint32 min, uint32 max)

{
  uint32 opres;
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 1;

  opres = fscanf(input, "%s", yes_no_buffer);
  if (opres == EOF || opres == 0) 
    return (nok);

  if (strcmp (yes_no_buffer, yes_string) == 0)
  {
    *out_buffer_ptr++ = 1;
  }
  else if (strcmp (yes_no_buffer, no_string) == 0)
  {
    *out_buffer_ptr++ = 0;
  }
  else
  {
    reperror(badYesNoErr, ifilename, yes_no_buffer);
    return (nok);
  }


  return (ok);
}

int32	get_mgr_ip_addr_string(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint8	mgrIpAddresses[maxManagerAddresses+1][4];   

  /*add one for overwrite
    -from fscanf in extractIpFromInputStream which takes 16 bit only!! */

  uint8	i, space;

  for (i=0;i<maxManagerAddresses;i++)
  {
    opres = extractIpFromInputStream(&mgrIpAddresses[i][0]);
    if (opres != ok) 
      return(opres);
    opres = fscanf(input, "%c", &space);
    if (opres == EOF || opres == 0)
      return (nok); 
  }
	

  /* perform range checks here */
  
  
  /* now write out the code: length: value group to the output buffer */ 
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4*maxManagerAddresses;
  memcpy (out_buffer_ptr, mgrIpAddresses , 4*maxManagerAddresses);
  out_buffer_ptr+=4*maxManagerAddresses;


  return (ok);
}

int16 extractIpFromInputStream(uint8 *ip)
{
  int16	opres;
  uint8   ipAddressString[32];
  uint32  ipAddressInt;
  
  opres = fscanf(input, "%s", ipAddressString);
  if (opres == EOF || opres == 0) 
    return (nok);
  ipAddressInt = inet_addr(ipAddressString);
  memcpy (ip, &ipAddressInt, 4);
  return (ok);

}

	
int32	get_ip_addr(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint8	ipAddressString[32];
  uint32	ipAddressInt;
  
  opres = fscanf(input, "%s", ipAddressString);
  if (opres == EOF || opres == 0) 
    return (nok);
  ipAddressInt = inet_addr(ipAddressString);

  /* perform range checks here */


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4;
  memcpy (out_buffer_ptr, &ipAddressInt, 4);
  out_buffer_ptr+=4;


  return (ok);
}	
	

int32	get_mgr_mac_addr(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint8	mgrMacAddresses[maxManagerAddresses][6];
  uint8	i, space;

  for (i=0;i<maxManagerAddresses;i++)
  {
    opres = extractMacFromInputStream(&mgrMacAddresses[i][0]);
    if (opres != ok) 
      return(opres);
    opres = fscanf(input, "%c", &space);
    if (opres == EOF || opres == 0) 
      return (nok); 
  }
	

  /* perform range checks here */


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 6*maxManagerAddresses;
  memcpy (out_buffer_ptr, mgrMacAddresses , 6*maxManagerAddresses);
  out_buffer_ptr+=6*maxManagerAddresses;


  return (ok);

}


int16 extractMacFromInputStream (uint8 *mac) 
{
  int16	opres;
  uint16	i;  
  int	colon, thismac;	/*fscanf %x expects pointer to int */
  
  for (i=0;i<6;i++)
  {
    opres = fscanf(input, "%x", &thismac);
    if (opres == EOF || opres == 0) 
      return (nok); 
    mac[i] = (thismac & 0xff);	/* keep low byte */
    
    opres = fscanf(input, "%c", &colon);
    if (opres == EOF || opres == 0) 
      return (nok);
  }

  return (ok);
}	
	

int32	get_max_ld(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint	max_ld;
  uint32	net_max_ld, ld32;

  opres = fscanf(input, "%d", &max_ld);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */
  if ((max_ld > max) || (max_ld < min))
  {
    sprintf (errParaString, " %d", max_ld);
    reperror(badLoopDelayErr, ifilename, errParaString);
    return (nok);
  }


  /* now write out the code: length: value group to the output buffer */ 
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4;  
  ld32 = max_ld;
  net_max_ld = htonl(ld32);
  memcpy (out_buffer_ptr, &net_max_ld, 4);
  out_buffer_ptr+=4;

  return (ok);
}

  
int32	get_max_nodes(uint8 code, uint32 min, uint32 max)

{
  int16 opres;
  uint max_nodes;

  opres = fscanf(input, "%d", &max_nodes);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */
  if ((max_nodes > max) || (max_nodes < min))
  {
    sprintf (errParaString, " %d", max_nodes);
    reperror(badMaxNodesErr, ifilename, errParaString);
    return (nok);
  }

  
  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 1;
  *out_buffer_ptr++ = max_nodes;

  return (ok);
}


int32	get_min_contention(uint8 code, uint32 min, uint32 max)

{
  int16 opres;
  uint min_contention;

  opres = fscanf(input, "%d", &min_contention);
  if (opres == EOF || opres == 0) 
    return (nok);


  /* perform range checks here */
  if ((min_contention > max) || (min_contention < min))
  {
    sprintf (errParaString, " %d", min_contention);
    reperror(badMinContentionErr, ifilename, errParaString);
    return (nok);
  }


  /* now write out the code: length: value group to the output buffer */ 
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 1;
  *out_buffer_ptr++ = min_contention;

  return (ok);
}




  
int32	get_max_cdms(uint8 code, uint32 min, uint32 max)

{
  int16 opres;
  uint max_cdms;
  uint32 net_max_cdms, cdm32;

  opres = fscanf(input, "%d", &max_cdms);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */



  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4;  
  cdm32 = max_cdms;
  net_max_cdms = htonl(cdm32);
  memcpy (out_buffer_ptr, &net_max_cdms, 4);
  out_buffer_ptr+=4;

  return (ok);
}

int32	get_community_string(uint8 code, uint32 min, uint32 max)

{
  int16  opres;
  uint8 comm_string[max_comm_string_length];
  uint8 i;

  /* clear comm_string array */
  for (i=0; i<max_comm_string_length; i++)
  {
    comm_string[i] = 0;
  }
	
  opres = fscanf(input, "%s", comm_string);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */



  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = max_comm_string_length;
  memcpy (out_buffer_ptr, comm_string, max_comm_string_length);
  out_buffer_ptr+=max_comm_string_length;

  return (ok);
}   
    
void xor_keys(uint8 *in_key_1_ptr, uint8 *in_key_2_ptr, uint8 *out_key_ptr)
{
  uint32	i;

  for (i=0;i<key_length;i++)
  {
    *out_key_ptr++ = (*in_key_1_ptr++ ^ *in_key_2_ptr++);
  }
}




int32	get_changed_key(uint8 code, uint32 min, uint32 max)

{
  int16 i;  
  int16	opres;
  uint8 new_key[key_length];
  
  /* clear new_key buffer */
  
  for (i=0; i<key_length; i++)
    new_key[i] = 0;

  opres = fscanf(input, "%s", new_key);
  if (opres == NULL)
    return (nok);            
                      


  /* create the xor of the new key and the encoding key  */
  xor_keys(&new_key[0], &digest_input_buffer[0],&xor_result[0]); 

  /* put a change key record in the output buffer  */
  /* write out the code: length: value group  */
  /* write out the full key_length including any padding  */

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = key_length;
  memcpy (out_buffer_ptr, xor_result, key_length);
  out_buffer_ptr+=key_length;

  return (ok);
}


int32	get_key_id(uint8 code, uint32 min, uint32 max)

{ 
  int16	opres;
  uint8	new_key_id[key_length];  
  size_t	id_length;

  opres = fscanf(input, "%s", new_key_id); 

  if ((opres == EOF) || (opres == 0)) 
  {
    return (nok);
  }  
  
  /*add the key id record to the configuration data  */
  id_length = strlen(new_key_id);
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = (uint8)id_length;
  memcpy (out_buffer_ptr, new_key_id, id_length);
  out_buffer_ptr+=id_length;

  return (ok);
}
  
  
  
int32	get_max_concat(uint8 code, uint32 min, uint32 max) 
{ 
  int16 opres;
  uint data_rate;

  opres = fscanf(input, "%d", &data_rate);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */
  if ((data_rate > max) || (data_rate < min))
  {
    sprintf (errParaString, " %d", data_rate);
    reperror(badMaxConcatErr, ifilename, errParaString);
    return (nok);
  }


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 1;
  *out_buffer_ptr++ = data_rate;
  return (ok);
} 


int32	get_access_type(uint8 code, uint32 min, uint32 max)
{
  int16 opres;
  uint access_type;

  opres = fscanf(input, "%d", &access_type);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */
  if ((access_type > max) || (access_type < min))
  {
    sprintf (errParaString, " %d", access_type);
    reperror(accessTypeErr, ifilename, errParaString);
    return (nok);
  }


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 1;
  *out_buffer_ptr++ = access_type;         
  return (ok);
}


int32	get_max_rate(uint8 code, uint32 min, uint32 max)
{
  int16 opres;
  uint maxRateKbps;
  uint32 net_max_rate, maxRateBps;

  opres = fscanf(input, "%d", &maxRateKbps);
  if (opres == EOF || opres == 0)
    return (nok);


  /* perform range checks here */
  
  /* convert to bps from kbps */ 
  maxRateBps = (uint32)(maxRateKbps);
  maxRateBps = maxRateBps*1000;


  /* now write out the code: length: value group to the output buffer */ 
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4;
  net_max_rate = htonl(maxRateBps);
  memcpy (out_buffer_ptr, &net_max_rate, 4);
  out_buffer_ptr+=4;
          
  return (ok);
}



uint16	streamToHexAsc(uint8 *in_buffer_ptr, uint8 *out_buffer_ptr, uint16 length)

{
  uint8 value, index; 
  uint16 i;



  for (i=0; i<length; i++)
  {   
    /* convert input stream byte by byte and store in output buffer */ 
    value = *in_buffer_ptr++;
    index = ((value & 0xf0) >> 4); 		/*high nibble */  
    *out_buffer_ptr++ = hexasc[index];
    index = (value & 0x0f); 			/*low nibble */
    *out_buffer_ptr++ = hexasc[index];
  }
	
  return (i*2);  /*length of output buffer */

}  

int32	getEnetClientMacAddr(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint8	clientMacAddresses[maxClientAddresses][6];
  uint8	i, space;
  int16 number_addresses;

  if (code == client_mac_addr_code_16)
    number_addresses = 16;
  else if (code == client_mac_addr_code)
    number_addresses = 4;

  for (i=0;i<number_addresses;i++)
  {
    opres = extractMacFromInputStream(&clientMacAddresses[i][0]);
    if (opres != ok)
      return(opres);
    opres = fscanf(input, "%c", &space);
    if (opres == EOF || opres == 0) 
      return (nok); 
  }
	

  /* perform range checks here */


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 6*number_addresses;
  memcpy (out_buffer_ptr, clientMacAddresses , 6*number_addresses);
  out_buffer_ptr+=6*number_addresses;


  return (ok);

}

int32	get_encrypted_nets(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint8	encryptedNets[maxEncryptedNets+1][4];  
  /*add one for overwrite 
    -from fscanf in extractIpFromInputStream which takes 16 bit only!! */
  uint8	i, space;
	
  for (i=0;i<maxEncryptedNets;i++)
  {
    opres = extractIpFromInputStream(&encryptedNets[i][0]);
    if (opres != ok) 
      return(opres);
    opres = fscanf(input, "%c", &space);
    if (opres == EOF || opres == 0) 
      return (nok); 
  }
	

  /* perform range checks here */
  

  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4*maxEncryptedNets;
  memcpy (out_buffer_ptr, encryptedNets , 4*maxEncryptedNets);
  out_buffer_ptr+=4*maxEncryptedNets;
  /* perform range checks here */

  return (ok);

}


int32	getClientIpAddrString(uint8 code, uint32 min, uint32 max)

{
  int16	opres;
  uint8	clientIpAddresses[maxClientAddresses+1][4];   
  /*add one for overwrite 
    -from fscanf in extractIpFromInputStream which takes 16 bit only!! */
  uint8	i, space;
  int16 number_addresses;

  if (code == client_ip_addr_code_16)
    number_addresses = 16;
  else if (code == client_ip_addr_code)
    number_addresses = 4;




  for (i=0;i<number_addresses;i++)
  {
    opres = extractIpFromInputStream(&clientIpAddresses[i][0]);
    if (opres != ok)
      return(opres);
    opres = fscanf(input, "%c", &space);
    if (opres == EOF || opres == 0) 
      return (nok); 
  }
	

  /* perform range checks here */


  /* now write out the code: length: value group to the output buffer */ 
  
  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4*number_addresses;
  memcpy (out_buffer_ptr, clientIpAddresses , 4*number_addresses);
  out_buffer_ptr+=4*number_addresses;


  return (ok);
}


int32	getDecimalNumber(uint8 code, uint32 min, uint32 max)

/* 
   gets a decimal mumber to two places multiplies by 100 and stores as an integer 
   extract the integer part
   multiply by 100
   extract the first decimal place
   multiply by 10 and add to integer
   extract the second decimal place and add to integer
*/
{
  int16 opres;
  int number_int, number_dec10, number_dec100;
  uint32 number_whole, net_number;
  uint8	decimal_point;

  opres = fscanf(input, "%d", &number_int); 
  
  if ((opres == EOF) || (opres == 0)) 
  {
    return (nok);
  }  
  number_whole = number_int*100;
    
  opres = fscanf(input, "%c", &decimal_point);
  if ((opres == EOF) || (opres == 0)) 
  {
    return (nok);
  }

  /* check for anything after the decimal point
     -access will not put it in if it is .00 */

  if (decimal_point == 0x2e)
  {	   
    opres = fscanf(input, "%1d", &number_dec10); 

    if ((opres == EOF) || (opres == 0)) 
    {
      return (nok);
    }
    number_dec10 = number_dec10*10;
    number_whole = number_whole + number_dec10;
    
    opres = fscanf(input, "%1d", &number_dec100); 
    if (opres == EOF) 
    {
      return (nok);
    }
    if (opres != 0) 
    {
      number_whole = number_whole + number_dec100;
    }
  }


  /* perform range checks here */


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = 4; 
  net_number = htonl(number_whole);
  memcpy (out_buffer_ptr, &net_number, 4);
  out_buffer_ptr+=4;

  return (ok);
}	



int32	getString(uint8 code, uint32 min, uint32 max)

{
  int16  opres,i, stringLength;
  int8 inString[max_string_length];

  
  /* clear string array */
  for (i=0; i<max_string_length; i++)
  {
    inString[i] = 0;
  }
	
  opres = fscanf(input, "%s", inString);
  if (opres == EOF || opres == 0)
    return (nok);
  stringLength = strlen(inString);

  /* perform range checks here */
  


  /* now write out the code: length: value group to the output buffer */ 

  *out_buffer_ptr++ = code;
  *out_buffer_ptr++ = stringLength;
  memcpy (out_buffer_ptr, inString, stringLength);
  out_buffer_ptr+=stringLength;

  return (ok);
}   


int32	comment_line(uint8 code, uint32 min, uint32 max)

{ 

  /* do nothing clear comment string will remove the line*/

  return (ok);
}   

int32	get_mib(uint8 code, uint32 min, uint32 max)
{
  return MibVarBind();
}	
