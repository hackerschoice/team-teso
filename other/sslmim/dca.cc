/*
 * Copyright (C) 2001 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "session.h"
#include "misc.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

using namespace NS_Misc;

extern bool use_subject_for_issuer;

namespace NS_DCA {

#ifndef MBSTRING_ASC
#warning "You use outdated openssl lib."
#define MBSTRING_ASC (0x1000|1)
#endif

// Note that 'subject' can be actually an issuer too.
// both, subject and issuer change is done by that function
char *change_name(X509_NAME *subject, char *peer_subject, bool ca_team)
{
	struct {
		char  C[256], ST[256], L[256], O[256], OU[256],
	     	      CN[256], Email[256];
	} sub;
	int len = 0;

	memset(&sub, 0, sizeof(sub));
	char *s = peer_subject;

	// begin ugly parsing ...
	if (strstr(s, "/C=")) {
		s = strstr(s, "/C=") + 3;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.C, s, len < 256 ? len : 255);
		s += len;
	}
	if (strstr(s, "/ST=")) {
		s = strstr(s, "/ST=") + 4;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.ST, s, len < 256 ? len : 255);
		s += len;
	}

	if (strstr(s, "/L=")) {
		s = strstr(s, "/L=") + 3;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.L, s, len < 256 ? len : 255);
		s += len;
	}

	if (strstr(s, "/O=")) {
		s = strstr(s, "/O=") + 3;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.O, s, len < 256 ? len : 255);
		s += len;
	}

	if (strstr(s, "/OU=")) {
		s = strstr(s, "/OU=") + 4;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.OU, s, len < 256 ? len : 255);
		s += len;
	}

	if (strstr(s, "/CN=")) {
		s = strstr(s, "/CN=") + 4;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.CN, s, len < 256 ? len : 255);
		s += len;
	}

	if (strstr(s, "/Email=")) {
		s = strstr(s, "/Email=") + 7;
		len = strchr(s, '/') ? strchr(s, '/') - s : strlen(s);
		memcpy(sub.Email, s, len < 256 ? len : 255);
		s += len;
	}

	if (sub.C[0])
		X509_NAME_add_entry_by_txt(subject,"C",
                      MBSTRING_ASC, (unsigned char*)sub.C, -1, -1, -1);

	if (sub.ST[0])
		X509_NAME_add_entry_by_txt(subject,"ST",
                      MBSTRING_ASC, (unsigned char*)sub.ST, -1, -1, -1);

	if (sub.L[0])
		X509_NAME_add_entry_by_txt(subject,"L",
                      MBSTRING_ASC, (unsigned char*)sub.L, -1, -1, -1);

	if (sub.O[0])
		X509_NAME_add_entry_by_txt(subject,"O",
                      MBSTRING_ASC, (unsigned char*)sub.O, -1, -1, -1);

	if (ca_team) {
		char fake[1024];
		memset(fake, 0, sizeof(fake));
		snprintf(fake, sizeof(fake), "%s ", sub.OU);
		X509_NAME_add_entry_by_txt(subject,"OU",
               		MBSTRING_ASC, (unsigned char*)fake, //"CA-Team", 
			-1, -1, -1);
	} else {
		X509_NAME_add_entry_by_txt(subject,"OU",
               		MBSTRING_ASC, (unsigned char*)sub.OU,
			-1, -1, -1);
	}

	if (sub.CN[0])
		X509_NAME_add_entry_by_txt(subject,"CN",
                      MBSTRING_ASC, (unsigned char*)sub.CN, -1, -1, -1);

	if (sub.Email[0])
		X509_NAME_add_entry_by_txt(subject,"Email",
                      MBSTRING_ASC, (unsigned char*)sub.Email, -1, -1, -1);
	
	return strdup(sub.CN);
}


// Do the somewhat tricky dynamic certificate assembly
// which puts "apropriate" subject and public key into
// X509 cert.
int do_dca(CSession *client, SSession *server)
{
	char l[1024];
	
	X509 *peer_cert = SSL_get_peer_certificate(client->ssl());

	if (!peer_cert) {
		log("Nuts, no server-certificate");
		return 0;
	}

	char *peer_subject = X509_NAME_oneline(
	    X509_get_subject_name(peer_cert), NULL, 0);
	char *peer_issuer  = X509_NAME_oneline(
	    X509_get_issuer_name(peer_cert), NULL, 0);

	log(peer_subject);
	log(peer_issuer);

	// name of algo which is used by server
	// (WE are client, and so 'client' is connection
	// to real server
	const char *algo = SSL_get_cipher(client->ssl());

	snprintf(l, sizeof(l), "Using cipher %s", algo);
	log(l);

	// what we loaded with load_keys()
	X509 *our_cert = SSL_get_certificate(server->ssl());
	
	X509_NAME *subject = X509_get_subject_name(our_cert);
	X509_NAME *issuer = X509_get_issuer_name(our_cert);

	// built our cert w/ subject of orig server
	char *name = change_name(subject, peer_subject, 0);
	X509_set_subject_name(our_cert, subject);

	// if we must 'touch' issuer, we will adopt the
	// the subject for the issuer, so that i.e. veri-signed
	// cert's become self-signed :)
	if (use_subject_for_issuer)
		change_name(issuer, peer_subject, 1);
	else
		change_name(issuer, peer_issuer, 1);

	X509_set_issuer_name(our_cert, issuer);

	// finally, set serialnumber
	ASN1_INTEGER *serial = X509_get_serialNumber(peer_cert);

	
	if (serial)
		X509_set_serialNumber(our_cert, serial);
	else
		log("Nuts, no serialnumber!");
	
	if (name) {
		// save fake-cert
		char save_cert[1024];
		snprintf(save_cert, sizeof(save_cert), "./cert_of_%s.%d", 
			 name, getpid());
	
		FILE *f = fopen(save_cert, "w+");
		if (!f)
			return 0;
		BIO *bio = BIO_new_fp(f, 0);
		PEM_write_bio_X509(bio, our_cert);
		BIO_flush(bio);
		fclose(f);
		free(name);
	}
	return 0;
}

}; // namespace NS_DCA

