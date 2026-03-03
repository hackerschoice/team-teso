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
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/stat.h>

extern "C" {
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
};

#include <pthread.h>

#include "ssh.h"
#include "misc.h"
#include "base64.h"

using namespace std;

DH *dh_new_group_asc(const char *gen, const char *modulus)
{
	DH *dh;

	dh = DH_new();
	if (dh == NULL)
		fprintf(stderr, "DH_new returned NULL");

	if (BN_hex2bn(&dh->p, modulus) == 0)
		fprintf(stderr, "BN_hex2bn (p) returned 0");
	if (BN_hex2bn(&dh->g, gen) == 0)
		fprintf(stderr, "BN_hex2bn (g) returned 0");

	return (dh);
}

/*
 * This just returns the group, we still need to generate the exchange
 * value.
 */

DH *dh_new_group(BIGNUM *gen, BIGNUM *modulus)
{
	DH *dh;

	dh = DH_new();
	if (dh == NULL)
		fprintf(stderr, "DH_new returned NULL");
	dh->p = modulus;
	dh->g = gen;

	return (dh);
}

DH *dh_new_group1(void)
{
	static char *gen = "2", *group1 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF";

	return (dh_new_group_asc(gen, group1));
}


int SSH2::packet_write(const void *buf, size_t buflen)
{
	unsigned char packet[32768], pad[16],
	              padding, mac[20];
	unsigned char *ptr = packet, *enc_packet = NULL;
	unsigned short paylen = 0;
	size_t mac_len = sizeof(mac);
	int r;

	assert(buflen < 32000);

	padding = 8 - ((buflen+1+4) % 8);
	if (padding < 4)
		padding += 8;
	*(u_int32_t*)ptr = htonl(buflen+1+padding);	// paylen
	ptr += sizeof(u_int32_t);
	paylen += sizeof(u_int32_t);
	*ptr = padding;
	++ptr;
	++paylen;
	memcpy(ptr, buf, buflen);
	ptr += buflen;
	paylen += buflen;
	memcpy(ptr, pad, padding);
	paylen += padding;
	ptr += paylen;

	if (use_crypto) {
		HMAC_CTX c;
		u_int32_t s = htonl(seq);
		HMAC_Init(&c, s_mac, sizeof(s_mac), EVP_sha1());
		HMAC_Update(&c, (unsigned char*)&s, sizeof(s));
		HMAC_Update(&c, packet, paylen);
		HMAC_Final(&c, mac, &mac_len);
	}

	++seq;	// one more packet written
	if (debug > 0)
		fprintf(stderr, "sending %d byte (%d padding) ", paylen, padding);

	if (use_crypto) {
		if (debug > 0)
			fprintf(stderr, "crypted\n");
		enc_packet = new unsigned char[paylen+mac_len];
		des_ede3_cbc_encrypt(packet, enc_packet, paylen,
	                     s_key1, s_key2, s_key3,
			     &s_iv, DES_ENCRYPT);
		memcpy(enc_packet+paylen, mac, mac_len);
		r = writen(peer, enc_packet, paylen+mac_len);
		delete [] enc_packet;
	} else {
		if (debug > 0)
			fprintf(stderr, "plain\n");
		r = writen(peer, packet, paylen);
		if (r <= 0) {
			error = "SSH2::packet_write::write(): ";
			error += strerror(errno);
		}
	}
	return r;
}


// return the number bytes read or -1 on error
// puts length of payload in n. packet may be trunced if
// plen < 32768
int SSH2::packet_read(unsigned char *plain_buf, size_t pblen, size_t *n)
{
	unsigned char buf[32768], *ptr = NULL;
	unsigned char dec_packet[32768];

	int r;

	if ((r = read(peer, buf, sizeof(buf))) <= 0) {
		error = "SSH2::packet_read::read() ";
		error += strerror(errno);
		return -1;
	}

	// maybe TODO: check MAC
	if (use_crypto) {
		if (r - 20 < 0) {
			error = "SSH2::read_packet: Invalid packet ";
			return -1;
		}
		des_ede3_cbc_encrypt(buf, dec_packet, r-20,
	                     r_key1, r_key2, r_key3,
			     &r_iv, DES_DECRYPT);
		ptr = dec_packet;
	} else
		ptr = buf;

	*n = ntohl(*(u_int32_t*)ptr);
	ptr += sizeof(u_int32_t);
	*n -= *ptr;	// minus paylen
	--*n;		// minus one
	if (*n > (size_t)r) {
		error = "SSH2::packet_read: bad packet size";
		return -1;
	}
	
	++ptr;
	memcpy(plain_buf, ptr, pblen < *n ? pblen : *n);
	return r;
}


int SSH2::banner_exchange()
{
	int r;
	char buf[1024], banner[] = "SSH-2.0-guess-who\r\n";

	// Add V_C to hash input
	to_hash_len = strlen(banner)-2 + sizeof(u_int32_t);
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len);
	*(u_int32_t*)to_hash = htonl(strlen(banner)-2);
	memcpy(&to_hash[sizeof(u_int32_t)], banner, strlen(banner)-2);

	memset(buf, 0, sizeof(buf));
	if ((r = read(peer, buf, sizeof(buf))) <= 0) {
		error = "SSH2::banner_exchange::read() ";
		error += strerror(errno);
		return -1;
	}
	char *crlf;
	if ((crlf = strchr(buf, '\n')) != NULL)
		*crlf = 0;
	if ((crlf = strchr(buf, '\r')) != NULL)
		*crlf = 0;
	snprintf(d_banner, sizeof(buf), "%s", buf);

	// Add V_S to hash input
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+strlen(buf) + sizeof(u_int32_t));
	*(u_int32_t*)&to_hash[to_hash_len] = htonl(strlen(buf));
	to_hash_len += sizeof(u_int32_t);
	memcpy(&to_hash[to_hash_len], buf, strlen(buf));
	to_hash_len += strlen(buf);

	if ((r = writen(peer, banner, strlen(banner))) <= 0) {
		error = "SSH2::banner_exchange::writen() ";
		error = strerror(errno);
	}

	return 0;
}


int SSH2::kex_init()
{
	char my_kex_msg[] = 
		"\x14"	// SSH_MSG_KEXINIT
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		"\x00\x00\x00\x1a" "diffie-hellman-group1-sha1"	// kex algo
		"\x00\x00\x00\x07" "ssh-dss"	// server hostkey algo
		"\x00\x00\x00\x08" "3des-cbc"	// client to server enc algo
		"\x00\x00\x00\x08" "3des-cbc"	// server to client enc algo
		"\x00\x00\x00\x09" "hmac-sha1"	// client to server MAC algo
		"\x00\x00\x00\x09" "hmac-sha1"	// server to client MAC algo
		"\x00\x00\x00\x04" "none"	// client to server comp algo
		"\x00\x00\x00\x04" "none"	// server to client comp algo
		"\x00\x00\x00\x00"		// client to server language
		"\x00\x00\x00\x00"		// server to client language
		"\x00"
		"\x00\x00\x00\x00";
	unsigned char buf[1024], *ptr;
	int r;
	size_t n;

	// Add I_C to hash input
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+sizeof(my_kex_msg)-1+sizeof(u_int32_t));
	*(u_int32_t*)&to_hash[to_hash_len] = htonl(sizeof(my_kex_msg)-1);
	to_hash_len += sizeof(u_int32_t);
	memcpy(&to_hash[to_hash_len], my_kex_msg, sizeof(my_kex_msg)-1);
	to_hash_len += sizeof(my_kex_msg)-1;

	r = packet_write(my_kex_msg, sizeof(my_kex_msg)-1);
	if (r < 0) {
		error = "SSH2::kex_init::packet_write() ";
		error = strerror(errno);
		return -1;
	}
	if (packet_read(buf, sizeof(buf), &n) <= 0)
		return -1;
	ptr = buf;
	if (*ptr != SSH_MSG_KEXINIT) {
		error = "SSH2::kex_init: packet type != SSH_MSG_KEXINIT";
		return -1;
	}

	// Add I_S to hash input
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+n+sizeof(u_int32_t));
	*(u_int32_t*)&to_hash[to_hash_len] = htonl(n);
	to_hash_len += sizeof(u_int32_t);
	memcpy(&to_hash[to_hash_len], ptr, n);
	to_hash_len += n;

	return 0;
}


int SSH2::hash_helper(const char *letter, unsigned char d1[20],
	unsigned char d2[20], bool expand)
{
	EVP_MD_CTX md;
	EVP_DigestInit(&md, EVP_sha1());

	// shared_secret as mpint
	unsigned char *secret = new unsigned char[shared_secret_len+1+4];
	int h = *shared_secret & 0x80 ? 1 : 0;
	*(u_int32_t*)secret = htonl(shared_secret_len+h);
	secret[sizeof(u_int32_t)] = 0;
	memcpy(&secret[sizeof(u_int32_t)+h], shared_secret, shared_secret_len);

	EVP_DigestUpdate(&md, secret, shared_secret_len+h+4);
	EVP_DigestUpdate(&md, session_id, sizeof(session_id));
	EVP_DigestUpdate(&md, (unsigned char*)letter, 1);
	EVP_DigestUpdate(&md, session_id, sizeof(session_id));
	EVP_DigestFinal(&md, d1, NULL);

	// Our expansion gives 40bytes, enough for 3DES keys and IV's
	if (expand) {
		EVP_DigestInit(&md, EVP_sha1());
		EVP_DigestUpdate(&md, secret, shared_secret_len+h+4);
		EVP_DigestUpdate(&md, session_id, sizeof(session_id));
		EVP_DigestUpdate(&md, d1, 20); // sizeof(d1) == 4 !!!
		EVP_DigestFinal(&md, d2, NULL);
	}

	delete [] secret;
	return 0;
}


int SSH2::derive_keys()
{
	// First, compute HASH == session_id
	EVP_MD_CTX md;
	EVP_DigestInit(&md, EVP_sha1());
	EVP_DigestUpdate(&md, to_hash, to_hash_len);
	EVP_DigestFinal(&md, session_id, NULL);

	if (debug > 1)
		buffer_dump("session_id", session_id, sizeof(session_id));

	unsigned char d1[20], d2[20];
	hash_helper("A", d1, d2, 0); memcpy(s_iv, d1, 8);
	hash_helper("B", d1, d2, 0); memcpy(r_iv, d1, 8);

	// Now for the encryption keys: we need to expand to 24 byte
	hash_helper("C", d1, d2, 1);
	des_set_key((const_des_cblock*)d1, s_key1);
	des_set_key((const_des_cblock*)(d1+8), s_key2);

	// last 4 byte of d1 and first 4 byte of d2 build 3rd key. ufff.
	unsigned char dummy[8];
	memcpy(dummy, d1+16, 4); memcpy(dummy+4, d2, 4);
	des_set_key((const_des_cblock*)dummy, s_key3);
//	buffer_dump("C", d1, 20);
//	buffer_dump("C", d2, 4);


	hash_helper("D", d1, d2, 1);
//	buffer_dump("D", d1, 20);
//	buffer_dump("D", d2, 4);


	des_set_key((const_des_cblock*)d1, r_key1);
	des_set_key((const_des_cblock*)(d1+8), r_key2);
	memcpy(dummy, d1+16, 4); memcpy(dummy+4, d2, 4);
	des_set_key((const_des_cblock*)dummy, r_key3);

	// MAC keys have same length as their hashoutput of used
	// hashing function
	hash_helper("E", s_mac, d2, 0);
	hash_helper("F", r_mac, d2, 0);
	return 0;
}



int SSH2::dh_exchange()
{
	DH *e = dh_new_group1();

	// generate x as in secsh-draft
	e->priv_key = BN_new();
	if (BN_rand(e->priv_key, 1024, 0, 0) == 0) {
		error = "SSH2::dh_exchange::BN_rand() returned 0";
		return -1;
	}
	// compute e = g^x mod p
	if (DH_generate_key(e) == 0) {
		error = "SSH2::dh_exchange::DH_generate_key() returned 0";
		return -1;
	}
	unsigned char *e_bin = new unsigned char[BN_num_bytes(e->pub_key)+1+1+4];
	unsigned char *e_tmp = new unsigned char[BN_num_bytes(e->pub_key)];

	assert(e_bin && e_tmp);

	BN_bn2bin(e->pub_key, e_tmp);
	int h = *e_tmp & 0x80 ? 1 : 0;

	// send e as mpint across network
	e_bin[0] = SSH_MSG_KEXDH_INIT;

	// Somehow OpenSSH looks whether e is signed and adds 0x00 in front
	// if so (length incremented by one). 'h' is true when highbit is set
	// Thats why we mess with e_tmp: We need to add 0x00 in some cases and
	// stretch the length by one. Same for shared_secret few lines later.
	e_bin[5] = 0;
	*(u_int32_t*)&e_bin[1] = htonl(BN_num_bytes(e->pub_key)+h);
	memcpy(&e_bin[5+h], e_tmp, BN_num_bytes(e->pub_key));
	packet_write(e_bin, BN_num_bytes(e->pub_key)+h+1+4);

	delete [] e_tmp;


	size_t n;
	unsigned char server_blob[32768], *ptr = server_blob;
	if (packet_read(server_blob, sizeof(server_blob), &n) <= 0)
		return -1;

	if (*ptr != SSH_MSG_KEXDH_REPLY) {
		error = "SSH2::dh_exchange: type != SSH_MSG_KEXDH_REPLY";
		return -1;
	}
	++ptr;
	
	// hostkey is a string
	size_t hostkey_len = ntohl(*(u_int32_t*)ptr);


	// Add K_S to hash input, its already in string format
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+hostkey_len+sizeof(u_int32_t));
	memcpy(&to_hash[to_hash_len], ptr, hostkey_len+sizeof(u_int32_t));
	to_hash_len += hostkey_len + sizeof(u_int32_t);
	
	ptr += sizeof(u_int32_t);
	ptr += hostkey_len;

	// Add e to hash input, already in mpint format at &e_bin[1]
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+BN_num_bytes(e->pub_key)+h+4);
	memcpy(&to_hash[to_hash_len], e_bin+1, BN_num_bytes(e->pub_key)+h+4);
	to_hash_len += BN_num_bytes(e->pub_key)+h+4;

	delete [] e_bin;

	if (debug > 0)
		fprintf(stderr, "hostkey_len=%d\n", hostkey_len);

	// get f. f is mpint (which is same as string :)
	size_t f_len = ntohl(*(u_int32_t*)ptr);


	// Add f to hash input, already in mpint format
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+f_len+sizeof(u_int32_t));
	memcpy(&to_hash[to_hash_len], ptr, f_len+sizeof(u_int32_t));
	to_hash_len += f_len+sizeof(u_int32_t);

	// go to f
	ptr += sizeof(u_int32_t);

	BIGNUM *f = BN_new();
	BN_bin2bn(ptr, f_len, f);

	shared_secret = new unsigned char[DH_size(e)];
	shared_secret_len = DH_compute_key(shared_secret, f, e);

	// Add shared_secret to hash input
	// Once again, add 0x00 of it is signed
	h = *shared_secret & 0x80 ? 1 : 0;
	to_hash = (unsigned char*)realloc(to_hash, to_hash_len+shared_secret_len+sizeof(u_int32_t)+h);
	*(u_int32_t*)&to_hash[to_hash_len] = htonl(shared_secret_len+h);
	to_hash_len += sizeof(u_int32_t);
	to_hash[to_hash_len] = 0;
	memcpy(&to_hash[to_hash_len+h], shared_secret, shared_secret_len);
	to_hash_len += shared_secret_len+h;


	if (debug > 1)
		buffer_dump("shared_secret", shared_secret, shared_secret_len);
//	buffer_dump("to_hash", to_hash, to_hash_len);

	derive_keys();

	return 0;
}


int SSH2::newkeys()
{
	char c = SSH_MSG_NEWKEYS;
	int r = packet_write(&c, 1);
	use_crypto = 1;
	return r;
}


int SSH2::userauth_passwd(const char *user, const char *password)
{
	char preq[32768], *ptr = preq;
	size_t preq_len = 0, l, n;
	unsigned char reply[32768];

	assert(strlen(user) + strlen(password) < 32000);


	preq[0] = SSH_MSG_SERVICE_REQUEST;
	++ptr;
	*(u_int32_t*)ptr = htonl(12);
	ptr += sizeof(u_int32_t);
	memcpy(ptr, "ssh-userauth", 12);
	ptr += 12;
	packet_write(preq, ptr-preq);
	if (packet_read(reply, sizeof(reply), &n) < 0)
		return -1;
	if (reply[0] != SSH_MSG_SERVICE_ACCEPT) {
		error = "SSH2::userauth_passwd: 'ssh-userauth' message not accepted";
		sprintf(preq, "(%d)", reply[0]);
		error += preq;
		return -1;
	}	
	ptr = preq;
	preq[0] = SSH_MSG_USERAUTH_REQUEST;
	++ptr;
	++preq_len;

	*(u_int32_t*)ptr = htonl(strlen(user));
	ptr += sizeof(u_int32_t);
	preq_len += sizeof(u_int32_t);
	memcpy(ptr, user, strlen(user));
	ptr += strlen(user);
	preq_len += strlen(user);

	*(u_int32_t*)ptr = htonl((l = strlen("ssh-connection")));
	ptr += sizeof(u_int32_t);
	preq_len += sizeof(u_int32_t);
	memcpy(ptr, "ssh-connection", l);
	ptr += l;
	preq_len += l;

	*(u_int32_t*)ptr = htonl((l = strlen("password")));
	ptr += sizeof(u_int32_t);
	preq_len += sizeof(u_int32_t);
	memcpy(ptr, "password", l);
	ptr += l;
	preq_len += l;

	*ptr = 0;	// FALSE ;-)
	++ptr;
	++preq_len;

	*(u_int32_t*)ptr = htonl((l = strlen(password)));
	ptr += sizeof(u_int32_t);
	preq_len += sizeof(u_int32_t);
	memcpy(ptr, password, l);
	ptr += l;
	preq_len += l;

	packet_write(preq, preq_len);

	memset(reply, 0, sizeof(reply));
	do {
		if (packet_read(reply, sizeof(reply), &n) < 0)
			return -1;
	} while (reply[0] != SSH_MSG_USERAUTH_FAILURE && 
	         reply[0] != SSH_MSG_USERAUTH_SUCCESS);

	return (reply[0] == SSH_MSG_USERAUTH_FAILURE);
}

/* Only checks whether pubkey is valid */
int SSH2::userauth_pubkey(const char *user, const char *keyfile)
{
	struct stat st;
	unsigned char reply[1024];
	size_t n, l;
	
	FILE *f = fopen(keyfile, "r");
	if (!f || stat(keyfile, &st) < 0) {
		error = "SSH2::userauth_pubkey: ";
		error += strerror(errno);
		return -1;
	}
	char *buf = new char[st.st_size];
	fgets(buf, st.st_size, f);

	// jump over ssh-rsa
	char *keyblob64 = strstr(buf, "ssh-rsa ");
	if (!keyblob64) {
		error = "SSH2::userauth_pubkey: Wrong format of keyfile";
		return -1;
	}
	keyblob64 += 8;
	char *tmp = strchr(keyblob64, ' ');
	if (!keyblob64) {
		error = "SSH2::userauth_pubkey: Wrong format of keyfile";
		return -1;
	}

	// eliminate icke@dort
	*tmp = 0;


	// First, send SERVICE_REQUEST for userauth
	char preq[128], *ptr = preq;
	preq[0] = SSH_MSG_SERVICE_REQUEST;
	++ptr;
	*(u_int32_t*)ptr = htonl(12);
	ptr += sizeof(u_int32_t);
	memcpy(ptr, "ssh-userauth", 12);
	ptr += 12;
	packet_write(preq, ptr-preq);
	if (packet_read(reply, sizeof(reply), &n) < 0)
		return -1;
	if (reply[0] != SSH_MSG_SERVICE_ACCEPT) {
		error = "SSH2::userauth_passwd: 'ssh-userauth' message not accepted";
		return -1;
	}	
	

	// now send USERAUTH_REQUEST for ssh-connection
	// service
	size_t len = 1 + strlen(user) + 4 + strlen("ssh-connection") + 4 +
	             strlen("publickey") + 4 + 1 + strlen(keyblob64);
	char *p = new char [len];
	ptr = p;
	*ptr = SSH_MSG_USERAUTH_REQUEST;
	++ptr;
	*(u_int32_t*)ptr = htonl(l = strlen(user));
	ptr += sizeof(u_int32_t);
	memcpy(ptr, user, l);
	ptr += l;

	*(u_int32_t*)ptr = htonl(l = strlen("ssh-connection"));
	ptr += sizeof(u_int32_t);
	memcpy(ptr, "ssh-connection", l);
	ptr += l;

	*(u_int32_t*)ptr = htonl(l = strlen("publickey"));
	ptr += sizeof(u_int32_t);
	memcpy(ptr, "publickey", l);
	ptr += l;

	*ptr = 0;	// FALSE
	++ptr;

	*(u_int32_t*)ptr = htonl(l = strlen("ssh-rsa"));
	ptr += sizeof(u_int32_t);
	memcpy(ptr, "ssh-rsa", l);
	ptr += l;

	unsigned char *keyblob = new unsigned char [strlen(keyblob64)];
	l = b64_pton(keyblob64, keyblob, strlen(keyblob64));
	*(u_int32_t*)ptr = htonl(l);
	ptr += sizeof(u_int32_t);
	memcpy(ptr, keyblob, l);
	packet_write(p, ptr-p+l);

	delete [] p;
	delete [] buf;
	delete [] keyblob;

	do {
		if (packet_read(reply, sizeof(reply), &n) < 0)
			return -1;
	} while (reply[0] != SSH_MSG_USERAUTH_FAILURE && 
	         reply[0] != SSH_MSG_USERAUTH_PK_OK);

	return (reply[0] == SSH_MSG_USERAUTH_FAILURE);
}

