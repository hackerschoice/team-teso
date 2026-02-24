/*
 * Copyright (c) 1988 Regents of the University of California.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)ring.h	5.2 (Berkeley) 3/1/91
 *	$Id: ring.h,v 1.13 1996/08/13 08:43:28 dholland Exp $
 */

class datasink {
 public:
    virtual ~datasink() {}
    virtual int write(const char *buf, int len) = 0;
    virtual int writeurg(const char *buf, int len) = 0;
};

/*
 * This defines a structure for a ring buffer.
 */
class ringbuf {
 public:
    class source {
     public:
	virtual ~source() {}
	virtual int read(char *buf, int len) = 0;
    };
 protected:
    datasink *binding;
    source *srcbinding;

    char *buf;
    int size;   /* total size of buffer */
    int head;   /* next input character goes here */
    int tail;   /* next output character comes from here */
    int count;  /* chars presently stored in buffer */
    // The buffer is empty when head==tail.

    int marked;   /* this character is marked */

 public:
    /////// consume end

    // manual consume
    int gets(char *buf, int max);
    int getch(int *ch);
    void ungetch(int ch);
    int full_count() {
	return count;
    }

    // automatic consume
    int flush();

    /////// supply end

    // manual supply
    void putch(char c) { write(&c, 1); }
    void write(const char *buffer, int ct);
    void xprintf(const char *format, ...);
    int empty_count() { return size - count; }

    // automatic supply
    int read_source();

    /////// others
    void clear_mark() { marked = -1; }
    void set_mark() { marked = head; }

    int init(int size, datasink *sink, source *src);

    datasink *setsink(datasink *nu) {
	datasink *old = binding;
	binding = nu;
	return old;
    }

};

extern datasink *netsink, *ttysink, *nullsink;
extern ringbuf::source *netsrc, *ttysrc;

#define	NETADD(c)	{ netoring.putch(c); }
#define	NET2ADD(c1,c2)	{ NETADD(c1); NETADD(c2); }

