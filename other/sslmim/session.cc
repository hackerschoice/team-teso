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

#ifdef fileno
#undef fileno
#endif

extern "C" {
#include <openssl/ssl.h>
}

Session::Session()
{
	SSL_load_error_strings();
	SSLeay_add_all_algorithms();

	d_ssl = NULL;
	d_ctx = NULL;
	d_method = NULL;	
	d_socket = -1; 
}

Session::~Session()
{
	shutdown();
	SSL_CTX_free(d_ctx);
}

int Session::read(char *buf, int len)
{
	return SSL_read(d_ssl, buf, len);
}

int Session::write(char *buf, int len)
{
	return SSL_write(d_ssl, buf, len);
}

int Session::shutdown()
{
	if (d_ssl) {
		SSL_shutdown(d_ssl);
		SSL_free(d_ssl);
		d_ssl = NULL;
	}
	return 0;
}

int Session::start()
{
	shutdown();
	d_ssl = SSL_new(d_ctx);
	if (!d_ssl) {
		error = "Session::start::SSL_new() returned NULL";
		return -1;
	}
	return 0;
}

int Session::fileno(int fd)
{
	SSL_set_fd(d_ssl, fd);
	d_socket = fd;
	return fd;
}

int Session::fileno()
{
	return d_socket;
}

//-----

CSession::CSession()
	: Session()
{
	d_method = SSLv23_client_method();

	if (!d_method) {
		error = "CSession::CSession::SSLv23_client_method() returned NULL";
		throw -1;
	}
	
	d_ctx = SSL_CTX_new(d_method);

	if (!d_ctx) {
		error = "CSession::CSession::SSL_CTX_new() returned NULL";
		throw -1;
	}
	
}

CSession::~CSession()
{
}

int CSession::connect()
{
	if (!d_ssl)
		return -1;
	return SSL_connect(d_ssl);
}		

SSession::SSession()
	: Session()
{
	d_method = SSLv23_server_method();

	if (!d_method) {
		error = "SSession::SSession::SSLv23_server_method() returned NULL";
		throw -1;
	}
	
	d_ctx = SSL_CTX_new(d_method);

	if (!d_ctx) {
		error = "SSession::SSession::SSL_CTX_new() returned NULL";
		throw -1;
	}
	
}

SSession::~SSession()
{
}

int SSession::accept()
{
	return SSL_accept(d_ssl);
}

int SSession::load_files(const char *key_file, const char *cert_file)
{
	if (SSL_CTX_use_certificate_file(d_ctx, cert_file, 
	    SSL_FILETYPE_PEM)<0) {
		error = "SSession::load_key_file::SSL_CTX_use_certificate()"
			" returned < 0";
		return -1;
	}
	
	if (SSL_CTX_use_PrivateKey_file(d_ctx, key_file,
	    SSL_FILETYPE_PEM) < 0) {
		error = "SSession::load_key_file::SSL_CTX_use_PrivateKey_file()"
			" returned < 0";
		return -1;
	}

	if (SSL_CTX_check_private_key(d_ctx) < 0) {
		error = "SSession::SSL_CTX_check_private_key() returned < 0";
		return -1;
	}
	return 0;
}

