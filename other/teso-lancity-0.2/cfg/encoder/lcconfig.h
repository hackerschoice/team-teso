#ifndef _LCCONFIG_H_
#define _LCCONFIG_H_

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
 *       lcconfig.h - shared items	      
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


/* external routines */
/*
#ifndef UNIX_LCN
extern uint32	htonl(uint32);   
extern uint32	inet_addr(uint8 *); 
#endif
*/
extern void reperror(char *, char *, char *);

/* other externals */

extern char	* errHeader;

extern char	* infileOpenErr;
extern char	* outfileOpenErr;
extern char	* keyfileOpenErr;
extern char	* badLabelErr;
extern char	* keyMatchErr;
extern char	* infileCloseErr;
extern char	* outfileCloseErr;
extern char	* keyfileCloseErr;
extern char	* badFreqErr;
extern char * badParameterErr;
extern char	* badYesNoErr;

/*
extern char	* badLoopDelayErr;
extern char	* badKeyLengthErr;
extern char * badMaxNodesErr; 
extern char	* badMaxCDMsErr; 
extern char	* dataRateErr;
extern char	* accessTypeErr;
extern char	* badMinContentionErr;
extern char	* badMaxConcatErr; 
*/

extern int32 get_freq(uint8, uint32, uint32);
extern int32 get_yes_no(uint8, uint32, uint32);
extern int32 get_cpe_mac_addr(uint8, uint32, uint32);
extern int32 get_class_of_service(uint8, uint32, uint32);
extern int32 get_baseline_privacy(uint8, uint32, uint32);
extern int32 get_write_access(uint8, uint32, uint32);
extern int32 get_mib(uint8, uint32, uint32);
extern int32 get_vendor_id_config(uint8, uint32, uint32);
extern int32 get_vendor_specific_config(uint8, uint32, uint32);
extern int32 getInteger8(uint8, uint32, uint32);
extern int32 getInteger16(uint8, uint32, uint32);
extern int32 getInteger32(uint8, uint32, uint32);
extern int32 getIntegerNumber(uint8, uint32, uint32, int);   
extern int32 getString(uint8, uint32, uint32);
extern int32 comment_line(uint8, uint32, uint32);
extern int32 get11(uint8, uint32, uint32);
extern int32 get111(uint8, uint32, uint32);
extern int32 get14(uint8, uint32, uint32);
extern int32 get114(uint8, uint32, uint32);
extern int32 get1s(uint8, uint32, uint32);

extern int16 extractIpFromInputStream(uint8 *);   
extern int16 extractMacFromInputStream(uint8 *);
extern void cmtsDigest(void);
/* 
extern uint32	htonl(uint32); 
*/

extern void xor_keys(uint8 *, uint8 *, uint8 *);
extern void MD5digest (uint8 *, uint16, uint8 *);

extern int8	errParaString[64];

extern FILE	*input;
extern FILE	*output;
extern FILE	*keyfile;

extern uint8	ifilename[64];
extern uint8	ofilename[64];
extern uint8	keyfilename[64];

extern int16	iresult, oresult;
extern int8	label_string[32];
                         
uint8	line_buffer[256];
uint8	out_buffer[0x50000];
uint8	*out_buffer_ptr; 

typedef struct
	{
		char * string;
		int size;
	} comment_t;                                 
	
comment_t *comment;
                         
#define SNMP_WRITE_ACCESS_LABEL "SnmpWriteAccess"
#define SNMP_MIB_LABEL "SnmpMib"

#endif /* _LCCONFIG_H_ */
