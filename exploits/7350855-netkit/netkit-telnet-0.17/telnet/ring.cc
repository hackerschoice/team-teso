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
 */

/*
 * From: @(#)ring.c	5.2 (Berkeley) 3/1/91
 */
char ring_rcsid[] =
  "$Id: ring.cc,v 1.23 2000/07/23 03:25:09 dholland Exp $";

/*
 * This defines a structure for a ring buffer. 
 */

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include "ring.h"

class devnull : public datasink {
    virtual int write(const char *, int n) { return n; }
    virtual int writeurg(const char *, int n) { return n; }
};
static devnull nullsink_obj;
datasink *nullsink = &nullsink_obj;



int ringbuf::init(int sz, datasink *sink, source *src) {
    buf = new char[sz];
    size = sz;
    head = tail = 0;
    count = 0;
    marked = -1;

    binding = sink;
    srcbinding = src;

    return 1;
}

/////////////////////////////////////////////////// consume //////////////

int ringbuf::gets(char *rbuf, int max) {
    int i=0, ch;
    assert(max>0);
    while (getch(&ch)>0 && i<max-1) rbuf[i++] = ch;
    rbuf[i]=0;
    return i;
}

int ringbuf::getch(int *ch) {
    int rv = 0;
    if (count > 0) {
	if (tail==marked) {
	    rv = 2;
	    marked = -1;
	}
	else rv = 1;
	*ch = (unsigned char) buf[tail++];
	if (tail>=size) tail -= size;
	count--;
    }
    return rv;   /* 0 = no more chars available */
}

void ringbuf::ungetch(int ch) {
    int x = tail;
    x--;
    if (x<0) x += size;
    int och = buf[x];   /* avoid sign-extension and other such problems */
    if ((och&0xff) == (ch&0xff)) {
	tail = x;
	count++;
    }
    else {
	//assert(!"Bad ungetch");
	tail = x;
	count++;
    }
}

/*
 * Return value:
 *   -2: Significant error occurred.
 *   -1: No useful work done, data waiting to go out.
 *    0: No data was waiting, so nothing was done.
 *    1: All waiting data was written out.
 *    n: Some data written, n-1 bytes left.
 */
int ringbuf::flush() {
    assert(binding);
    assert(count>=0);
    if (count==0) return 0;
    
    static int busy=0;
    if (busy) {
	return -1;
    }
    busy=1;

    /* should always be true */
    /* assert(((size+head-tail)%size)==count); */
    /* Nope! The above fails if the buffer is full; then:
     * head == tail (so LHS is 0), but count == size.
     * The following formula should be better. --okir */
    assert(((head - tail - count) % size) == 0);

    while (count > 0) {
	int bot = tail;
	int top = head;
	if (top < bot) top = size;
	if (marked > bot) top = marked;
	assert(top-bot > 0 && top-bot <= count);

	int n;
	if (marked==bot) n = binding->writeurg(buf+bot, top-bot);
	else n = binding->write(buf+bot, top-bot);
	if (n < 0) { busy=0; return -2; }
	else if (n==0) { busy=0; return -1; }
	
	if (marked==bot) marked = -1;
	tail += n;
	if (tail >= size) tail -= size;
	count -= n;
	assert(((size+head-tail)%size)==count);
	
	if (n > 0 && n < top-bot) { busy=0; return n+1; }
	/* otherwise (if we wrote all data) loop */
    }
    assert(((size+head-tail)%size)==count);
    busy=0;
    return 1;
}


/////////////////////////////////////////////////// supply //////////////

void ringbuf::xprintf(const char *format, ...) {
    char xbuf[256];
    va_list ap;
    va_start(ap, format);
    int l = vsnprintf(xbuf, sizeof(xbuf), format, ap);
    va_end(ap);
    write(xbuf, l);
}

void ringbuf::write(const char *buffer, int ct) {
    if (ct > size - count) {
	// Oops. We're about to overflow our buffer.
	// In practice this shouldn't ever actually happen.
	// We could return a short count, but then we'd have to check
	// and retry every call, which ranges somewhere between painful
	// and impossible.
	// Instead, we drop the data on the floor. This should only happen 
	// if (1) the tty hangs, (2) the network hangs while we're trying 
	// to send large volumes of data, or (3) massive internal logic errors.
	fprintf(stderr, "\n\ntelnet: buffer overflow, losing data, sorry\n");
	ct = size - count;
    }
    for (int i=0; i<ct; i++) {
	buf[head++] = buffer[i];
	if (head>=size) head -= size;
	count++;
    }
}

int ringbuf::read_source() {
    int bot = head;
    int top = tail-1; /* leave room for an ungetc */
    if (top<0) top += size;
    if (top < bot) top = size;

    if (top==bot) return 0;

    int l = srcbinding->read(buf+bot, top-bot);
    if (l>=0) {
	head += l;
	if (head>=size) head -= size;
	count += l;
    }
    if (l==0) l = -1;
    return l;
}
