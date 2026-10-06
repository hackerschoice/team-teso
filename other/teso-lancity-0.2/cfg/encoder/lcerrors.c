/*
 ***********************************************************************
 *                                                                      
 *      	Copyright 1995 by Applitek / LANcity Corporation            
 *                                                                      
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
 *       lcstring.c - error messages	      
 *                                                                            *
 * REVISION HISTORY                                                           *
 *                                                                            *
 * DATE        AUTHOR REASON FOR CHANGE                                       *
 *                                                                            *
 *                       
 *	03/28/95	gw	initial version   
 *	04/10/95	gw 	report error using message box
 *	08/08/96	gw	port to unix
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

 

/*
 ******************************************************************************
 *                                                                            *
 * DEFINES FOLLOW
 *                                                                            *
 ******************************************************************************
*/    
#ifndef UNIX_LCN
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>

#include "lctypes.h"

#if 0
 
uint8	errHeader[] = "Program Error";

uint8	infileOpenErr[] = "read file open error";
uint8	outfileOpenErr[] = "write file open error";
uint8	keyfileOpenErr[] = "key file open error";
uint8	badLabelErr[] = "bad label field";
uint8	keyMatchErr[] = "can't match key id ";
uint8	infileCloseErr[] = "input file close error";
uint8	outfileCloseErr[] = "output file close error";
uint8	keyfileCloseErr[] = "key file close error";
uint8	badFreqErr[] = "bad frequency value";
uint8	badYesNoErr[] = "bad value - not yes or no"; 
uint8	badLoopDelayErr[] = "bad loop delay value";
uint8	badKeyLengthErr[] = "bad key length";
uint8	badMaxNodesErr[] = "bad max nodes value"; 
uint8	badMaxCDMsErr[] = "bad max nodes value"; 
uint8	accessTypeErr[] = "bad access type value";
uint8	dataRateErr[] = "bad data rate value";  
uint8	badMinContentionErr[] = "bad min. contention value";
uint8	badMaxConcatErr[] = "bad max. concatenation value";
uint8	badParameterErr[] = "bad parameter value";
#else


 
uint8	*errHeader           = "Program Error";
uint8	*infileOpenErr       = "read file open error";
uint8	*outfileOpenErr      = "write file open error";
uint8	*keyfileOpenErr      = "key file open error";
uint8	*badLabelErr         = "bad label field";
uint8	*keyMatchErr         = "can't match key id ";
uint8	*infileCloseErr      = "input file close error";
uint8	*outfileCloseErr     = "output file close error";
uint8	*keyfileCloseErr     = "key file close error";
uint8	*badFreqErr          = "bad frequency value";
uint8	*badYesNoErr         = "bad value - not yes or no"; 
uint8	*badLoopDelayErr     = "bad loop delay value";
uint8	*badKeyLengthErr     = "bad key length";
uint8	*badMaxNodesErr      = "bad max nodes value"; 
uint8	*badMaxCDMsErr       = "bad max nodes value"; 
uint8	*accessTypeErr       = "bad access type value";
uint8	*dataRateErr         = "bad data rate value";  
uint8	*badMinContentionErr = "bad min. contention value";
uint8	*badMaxConcatErr     = "bad max. concatenation value";
uint8	*badParameterErr     = "bad parameter value";


#endif

uint8	error_msg[128];
uint8	spaces[]="  ";  


void   reperror(uint8 *err_ptr, uint8 *filename, uint8 *parameter_string)

{     

strcpy(error_msg, err_ptr); 
strcat(error_msg, spaces);
strcat(error_msg, filename); 
strcat(error_msg, spaces);
strcat(error_msg, parameter_string);

	printf ("%s \n", error_msg);

}
 
                        
                          
