LANcity Provisioning Server File Conversion Utility
===================================================
Reference Implementation
========================


Disclaimer
----------
This code is provided on an as is basis. 
It is not a supported LANcity product.
This is to be used as an example for new features
  implemented in software release V4.00.  The 
  maximum md5 output file must not be larger than
  16384 bytes.  Any file over 4096 bytes is not 
  backwards compatible with previous software 
  releases.

Package Content
---------------
Readme file readme.txt (this file).
Readme file readme.doc (this file in MS Word format).
Release notes relnotes.txt.
Source and include files for LANcity file conversion utility.
Makefile set up for GNU compiler & SunOs.
Sample configuration files.
This includes the .md5 output file which should be created from the provided 
input file & key file. This can be used to determine if a port is successful.

Installation
------------
	Unpack the file UnixLcn400.tar using the command 
	tar -xvf UnixLcn400.tar.

Operation
---------

	Two utilities are supplied.  LcnConvert creates the .md5.
	lcn_decode will display the .md5 file.

	The utility is run from the command line as below
	LcnConvert <input-file> <output-file> <key-file>
	input-file is the file name of the ascii config file (.cfg)
	output-file is the file name of the binary config file (.md5)
	key-file is the file name of the (ascii) key file which will
	be included in the MD5 digest.


	lcn_decode is run from the command line as below
	cat <input-file> | lcn_decode
	input-file is the file name of the binary config file (.md5)

Include Files
-------------

lctypes.h
	This file contains definitions for chars, ints etc. to allow
	the code to be portable between Unix & PC systems.
	These defines must be modified to reflect the target architecture.

confdata.h
	This file contains defines for the binary codes used in the .md5 file.

confdefs.h
	This file contains general defines used in the conversion.

asn1.h
	This file contains general types needed to asn1 encode data.

lcnmib.h
	This file contains function prototypes for the provisioning of
	snmp variables.

md5.h	
	This file contains general types needed to MD5 encode a file.
	
mib.h
	This file contains general types needed to create a mib entry.

snmp.h 
	This file contains general types for building and SNMP varbind.

snmpimpl.h
	This file contains general types for implementing SNMP enocded
	varbinds. 

Source Files
------------

lcn_decode.c
	This file contains the code which performs the parsing of the
	.md5.

lcconfig.c
	This file contains the code which performs the conversion 
	from the input text file to the required binary format.
	Entry to this processing is via the routine build_config_file.
	This is called from main with the file names passed as parameters.
	Each line of the input file is parsed, the token is extracted
	and processed according to the table decodeTable.
	decodeTable contains entries to control the processing of each 
	recognized token in the form
		token label
		processing routing
		minimum of valid range
		maximum of valid range
		binary code for this token type



lcerrors.c
	This file contains the routines to display error messages reported
	during the conversion.  The Unix version uses printf to the console
	the Win95 version uses a message box.

md5.c
	This file contains the MD5 algorithms.
	It is derived from the public domain implementation by Karn.

lcnmib.c
	This file contains the code which performs the conversion 
	from the input text file to the required SNMP Encoded Varbind
	format.  Entry to this processing is via the routine 
	build_config_file.  This is called from main with the file 
	names passed as parameters.  Each line of the input file is parsed, 
	the token is extracted and processed according to the table 
	decodeTable.  This file contains all processing for SNMP variable
	types which all have the same label.  This file has a decode table 
	which contains

		token label
		SNMP Variable Label
		processing routing
		Number of instances (always 1)
		SNMP object identifier

snmp.c
	This file actually builds the complete SNMP Encoded Varbind.
asn1.c
	This file contains the asn.1 encoding algorithms.  These
	are used to create and Encoded SNMP Varbind. ASN.1 encoding is
	defined in ISO/IS 8824 and ISO/IS 8825.

main.c
	User interface shell for unix version of the file conversion. 
	This provides the main procedure which runs when the 
	application is invoked from the command line.

Sample Files
------------

cdm1.cfg
	Example source file in the correct format for input by the 
	conversion program.  This file contains an entry for all supported
	tokens.

cdm2.cfg
	Example source file in the correct format for input by the 
	conversion programs.  It has all filter variables provisioned.

default.key
	A sample key data file containing the default key as shipped in 
	LANcity modems.

cdm1.md5
	Example output file in the correct format for an LCp.
	It is the expected output from processing cdm1.md5 using default.key.

cdm2.md5
	Example output file in the correct format for an LCp.
	It is the expected output from processing cdm1.md5 using default.key.

Porting
-------

The type definitions in file lctypes.h must be modified to reflect the target.
The makefile must be modified to reflect the target & the compiler to be used.
The definition UNIX_LCN is used to select a unix rather than PC implementation.
Type make to build the conversion utility.


Adding New Token Types
----------------------

Later versions of LANcity code will add additional token types as new
features are provided.  These types will be defined in the LCp Configuration 
Interface Specification document which may be ordered from LANcity as part
number 560-0069.

The new token must be added to the decodeTable together with the values
for minimum & maximum allowed range, and a pointer to a processing routine.

The processing routine must be written to convert the token & parameters 
to the required binary format.

A number of generic processing routines are provided which may be used for
many parameter types (IP adresses, MAC addresses ,...).

The succesful addition of a new token type can be confirmed by comparing
the results generated by the LANcity LCn utility (.cfg  & .md5 files) to
those of the Unix version.



The large "switch" in lcn_decode.c must also be update to reflect any
new tokens.
