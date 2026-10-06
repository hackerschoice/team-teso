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

static	char	config_data_h_SCCS_ID [ ] = "@(#)confdata.h	1.5 9/18/97 ";	


/*
 ******************************************************************************
 *                                                                            *
 * CONSTANTS AND MACROS FOLLOW                                                *
 *                                                                            *
 ******************************************************************************
*/
/* codes for BOOTP like output file */
 
#define tx_frequency_code       			1
#define rx_frequency_code      				2
#define reference_node_code     			3
#define max_ld_code             			4
#define digest_code             			5
#define change_key_code         			6
#define key_id_code         				7
#define join_net_code        				8  
#define net_mgmt_access_mode_code        	        9
#define freq_scan_code        				10
#define auto_install_code      				11
#define max_nodes_code        				12
/*#define mgr_ip_addr_code				13 */
/*#define mgr_mac_addr_code				14  */
#define maxcdm_code					15 
#define default_gw_code				       	16 
#define read_comm_code				       	17
#define write_comm_code				       	18
#define trap_comm_code				       	19 
#define max_concat_code				       	20
#define access_type_code			       	21
#define fwd_max_code				       	22
#define ret_max_code				       	23  
#define min_cont_code				       	24
#define mgr_ip_addr_code			       	25
#define mgr_mac_addr_code			       	26
#define client_mac_addr_code				27
#define encrypt_code				       	28
#define off_net_gateway_code				29 
#define key_server_code				       	30
#define encrypted_net_code			       	31
#define client_ip_addr_code			      	32
#define sw_rev_code				      	33
#define upgrade_file_code				34   
#define tftp_server_ip_addr_code			35


#define snmp_mib_code                                   38
#define lcnless_enabled_code                            39
#define client_mac_addr_code_16                         40
#define client_ip_addr_code_16                          41

#define end_code         		                255
#define pad_code       		                        0
  
#define max_key_id_length       16
#define key_length              64
#define min_key_length		16
   
#define digest_length           16

#define max_config_data         256 

#define max_comm_string_length	32

#define maxManagerAddresses		5 
#define maxClientAddresses		16 
#define maxEncryptedNets        10 /* 2 x nets as each net has address + mask entry*/

#define max_string_length	64

#endif		/* Required */
