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

#ifndef _SESSION_H_
#define _SESSION_H_

extern "C" {
#include <openssl/ssl.h>
}

#include <string>

class Session {
private:
	int d_socket;

	Session(const Session&);
	Session &operator=(const Session&);

protected:
	SSL_CTX *d_ctx;
	SSL *d_ssl;
	SSL_METHOD *d_method;

	string error;
	
	Session();

public:
	virtual ~Session();

	int read(char *buf, int len);

	int write(char *buf, int len);

	//! Get fileno (socket)
	int fileno();

#ifdef fileno
#undef fileno
#endif

	//! Set fileno (socket)
	int fileno(int fd);

	int shutdown();

	int start();

	//! Get SSL object for more SSL-stuff
	SSL* ssl() { return d_ssl; }

	//! ditto
	SSL_CTX *ctx() { return d_ctx; }

	//! Usual error-handling
	const char *why() { return error.c_str(); }
};

class CSession : public Session {
private:
	CSession(const CSession &);
	CSession &operator=(CSession &);
public:
	CSession();
	virtual ~CSession();

	int connect();
};

class SSession : public Session {
private:
	SSession(const SSession &);
	SSession &operator=(const SSession &);
public:
	SSession();
	virtual ~SSession();

	//! Load private key and certificate
	int load_files(const char *key_file, const char *cert_file);

	//! Wait for SSL handshake
	int accept();
};

#endif
	
