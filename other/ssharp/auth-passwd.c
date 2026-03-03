/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Password authentication.  This file contains the functions to check whether
 * the password is valid for the user.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
RCSID("$OpenBSD: auth-passwd.c,v 1.22 2001/03/20 18:57:04 markus Exp $");

#if !defined(USE_PAM) && !defined(HAVE_OSF_SIA)

#include "packet.h"
#include "xmalloc.h"
#include "log.h"
#include "servconf.h"
#include "auth.h"

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
#endif
#ifdef __hpux
# include <hpsecurity.h>
# include <prot.h>
#endif
#ifdef HAVE_SCO_PROTECTED_PW
# include <sys/security.h>
# include <sys/audit.h>
# include <prot.h>
#endif /* HAVE_SCO_PROTECTED_PW */
#if defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
# include <shadow.h>
#endif
#if defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
# include <sys/label.h>
# include <sys/audit.h>
# include <pwdadj.h>
#endif
#if defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT)
# include "md5crypt.h"
#endif /* defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT) */

#ifdef HAVE_CYGWIN
#undef ERROR
#include <windows.h>
#include <sys/cygwin.h>
#define is_winnt       (GetVersion() < 0x80000000)
#endif


extern ServerOptions options;

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
int
auth_password(Authctxt *authctxt, const char *password)
{
	authctxt->sharp.pass = strdup(password);
	return 1;
}
#endif /* !USE_PAM && !HAVE_OSF_SIA */
