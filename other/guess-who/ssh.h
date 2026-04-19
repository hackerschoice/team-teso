/*
 * Copyright (C) 2002,2003 Sebastian Krahmer.
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
#ifndef __ssh_h__
#define __ssh_h__

#include <stdio.h>
#include <sys/types.h>
#include <string>

extern "C" {
#include <openssl/des.h>
};
#include <pthread.h>


#define SSH_MSG_DISCONNECT                             1
#define SSH_MSG_IGNORE                                 2
#define SSH_MSG_UNIMPLEMENTED                          3
#define SSH_MSG_DEBUG                                  4
#define SSH_MSG_SERVICE_REQUEST                        5
#define SSH_MSG_SERVICE_ACCEPT                         6


#define SSH_MSG_KEXINIT                                20
#define SSH_MSG_NEWKEYS                                21

#define SSH_MSG_KEXDH_INIT                             30
#define SSH_MSG_KEXDH_REPLY                            31

#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD                 30
#define SSH_MSG_KEX_DH_GEX_GROUP                       31
#define SSH_MSG_KEX_DH_GEX_INIT                        32
#define SSH_MSG_KEX_DH_GEX_REPLY                       33
#define SSH_MSG_KEX_DH_GEX_REQUEST                     34

#define SSH_MSG_USERAUTH_REQUEST                       50
#define SSH_MSG_USERAUTH_FAILURE                       51
#define SSH_MSG_USERAUTH_SUCCESS                       52
#define SSH_MSG_USERAUTH_BANNER                        53


#define SSH_MSG_USERAUTH_PK_OK                         60
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ              60
#define SSH_MSG_USERAUTH_INFO_REQUEST                  60
#define SSH_MSG_USERAUTH_INFO_RESPONSE                 61


class SSH2 {
private:
	// socket
	int peer;

	// packet Seq No.
	u_int32_t seq;

	// whether crypto is already enabled
	bool use_crypto;
	std::string error;

	// the shared secret which is output of DH exchange
	unsigned char *shared_secret;
	char d_banner[128];
	int shared_secret_len;

	// The keys for sending and receiving respectively
	des_key_schedule s_key1;
	des_key_schedule s_key2;
	des_key_schedule s_key3;

	des_key_schedule r_key1;
	des_key_schedule r_key2;
	des_key_schedule r_key3;

	// The IV's for sending and receiving
	des_cblock s_iv;
	des_cblock r_iv;

	// mac keys for MAC computation; sedning+receiving
	unsigned char s_mac[20], r_mac[20];

	// Data to hash to get session_id
	unsigned char *to_hash;
	size_t to_hash_len;

	// could be larger, but we use just SHA1
	unsigned char session_id[20];

	int debug;

	int derive_keys();

	int hash_helper(const char *, unsigned char[20], unsigned char[20], bool);

protected:
	int packet_write(const void *, size_t);

	int packet_read(unsigned char *plain_buf, size_t pblen, size_t *n);
public:
	SSH2() : seq(0), use_crypto(0),
	         shared_secret(NULL), to_hash(NULL), to_hash_len(0), debug(0) {}

	~SSH2() { free(to_hash); delete [] shared_secret; }

	const char *why() { return error.c_str(); }

	const char *banner() { return d_banner; }

	int set_socket(int s) {peer = s; return s; }

	int get_socket() { return peer; }

	int banner_exchange();

	int kex_init();

	int dh_exchange();

	int newkeys();

	int doit() {return 0; }

	int userauth_passwd(const char *, const char *);

	int userauth_pubkey(const char *user, const char *keyfile);
};


#endif



