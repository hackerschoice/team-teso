/*------------------------------------------------------------------*
 *	Copyright  (c) 1995 LANcity Corporation -  All rights reserved
 *
 *	Description:                                                            
 *
 *  		 Server application for the LCP
 *		 -only used in Unix implementation
 *  
 *  File: main.c
 *
 *
 *
 *------------------------------------------------------------------*/ 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "lctypes.h"


/* external routines */

int16 build_config_file (uint8 * ifilename, uint8 *ofilename, uint8 *keyfilename);


uint8 version[] = "3.20";
    
    

main(argc,argv)
int16 argc;
uint8 **argv;
{
  uint8 *inFile, *outFile, *keyFile;
  
  printf("LANcity LCN Unix Reference Implementation Version ");
  printf("%s", version);
  printf("\n");
  printf("\n");
 
  if( argc != 4) {
    printf("Usage: LcnConvert <input-file> <output-file> <key-file> \n");
    exit(-1);
  }
  inFile = *(++argv);
  printf("Input file: %s\n", inFile);
  outFile = *(++argv);
  printf("Output file: %s\n", outFile);
  keyFile = *(++argv);
  printf("Key file: %s\n", keyFile);
  
  build_config_file (inFile, outFile, keyFile); 

  exit(0);
}
 
