/*
 ******************************************************************************
 *                                                                            *
 *      	Copyright 1992 by Applitek / LANcity Corporation              *
 *                                                                            *
 *  PROPRIETARY RIGHTS of Applitek Corp are involved in the                   *
 *  subject matter of this material.  All manufacturing, reproduction,        *
 *  use, and sales rights pertaining to this subject matter are               *
 *  governed by the license agreement.  The buyer or recipient of this        *
 *  package, implicitly accepts the terms of the license.                     *
 *                                                                            *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************
 *                                                                            *
 * FILE NAME AND DESCRIPTION                                                  *
 *                                                                            *
 *       config_data.h - definitions for use in LCP configuration 	      *
 *                                                                            *
 * REVISION HISTORY                                                           *
 *                                                                            *
 * DATE        AUTHOUR REASON FOR CHANGE                                      *
 *                                                                            *
 * 12/29/94    gw    Initial version                                          *
 * 05/24/95    cam   Initial version                                          *
 * 06/20/95    cam   NMREADONLY                                               *
 * 10/03/95    rwb   Added code for community strings                         *
 * 01/17/96    jmu   Added code for Allocator parms from LCN                  *
 * 01/20/96    cmb   changed values for AUTH_NM_IP and AUTH_NM_MAC            *
 *                   added OLD_AUTH_NM_IP and OLD_AUTH_NM_MAC                 *
 *                   changed MAX_CONFIG_DATA from 256 to 2048                 *
 * 04/04/96    cmb   added LCW_MAC_ADDRS                                      *
 * 04/20/96    rwb   Added LCN codes for encryption                           *
 * 08/15/96    cmb   Added LCN codes for 3.0                                  *
 *                                                                            *
 *  NOTES / RESTRICTIONS:                                                     *
 *                                                                            *
 ******************************************************************************
*/

/*
 ******************************************************************************
 *                                                                            *
 * UNIQUE PRE-PROCESSOR SYMBOL FOLLOWS
 *                                                                            *
 ******************************************************************************
*/
#ifndef		config_data_h
#define		config_data_h

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
 * SCCS_ID STRING FOLLOWS
 *                                                                            *
 ******************************************************************************
*/

static	char	config_data_h_SCCS_ID [ ] = "@(#)config_data.h	1.13 11/13/96 ";	


/*
 ******************************************************************************
 *                                                                            *
 * CONSTANTS AND MACROS FOLLOW                                                *
 *                                                                            *
 ******************************************************************************
*/
/* codes for BOOTP like output file */
 
#define TX_FREQUENCY_CODE       1
#define RX_FREQUENCY_CODE       2
#define REFERENCE_NODE_CODE     3
#define MAX_LD_CODE             4
#define DIGEST_CODE             5
#define CHANGE_KEY_CODE         6
#define KEY_ID_CODE         	7
#define ACCESS_NETWORK_CODE     8
#define NMREADONLY               9 
#define FREQ_SCAN_OVERRIDE_CODE 10
#define AUTO_INSTALL_OVERRIDE_CODE 11
#define MAX_NODES_ETHERNET      12
#define OLD_AUTH_NM_IP	        13
#define OLD_AUTH_NM_MAC	        14
#define MAX_NODES_BROADBAND     15 
#define DEFAULT_GW_IP_CODE      16 
#define SNMP_GET_COMM_CODE      17
#define SNMP_SET_COMM_CODE      18
#define SNMP_TRAP_COMM_CODE     19
#define MAX_CONCAT_SIZE	        20
#define DED_ACCESS_CTRL         21
#define MAX_FWD_BANDWIDTH       22
#define MAX_RET_BANDWIDTH       23
#define MIN_PUBLIC_CONTENTION   24
#define AUTH_NM_IP	        25
#define AUTH_NM_MAC	        26
#define LCW_MAC_ADDRS	        27

#define ENCRYPT_CODE	        28
#define OFF_NET_GATEWAY_CODE    29
#define KEY_SERVER_CODE	        30
#define ENCRYPTED_NET_CODE      31

/* 3.0 additions */
#define CLIENT_IP_ADDR      	32
#define SOFTWARE_REVISION      	33
#define UPGRADE_FILENAME      	34
#define TFTP_SERVER_IP_ADDR     35
#define GUARANTEED_BW     	36
#define RESERVED_BW     	37


#define END_CODE       		255
#define PAD_CODE       		0
  
#define MAX_KEY_ID_LENGTH       16
#define KEY_LENGTH              64
   
#define DIGEST_LENGTH           16

#define MAX_CONFIG_DATA         2048



#endif		/* Required */
