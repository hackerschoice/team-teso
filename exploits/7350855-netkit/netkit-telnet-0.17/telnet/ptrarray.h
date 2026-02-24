//
// 	File:        ptrarray.h
// 	Date:        16-Jul-95
//	Description: Array of pointers
//
/*
 * Copyright (c) 1995 David A. Holland.
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
 * 3. Neither the name of the Author nor the names of any contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef PTRARRAY_H
#define PTRARRAY_H

#ifndef assert
#include <assert.h>
#endif

#ifndef NULL
#define NULL 0
#endif

template <class T>
class ptrarray {
  protected:
    T **v;
    int n, max;
    void reallocto(int x) {
	while (max<x) max += 16;
	T **q = new T* [max];
	for (int i=0; i<n; i++) q[i] = v[i];
	delete []v;
	v = q;
    }
  public:
    ptrarray() { v=NULL; n=max=0; }
    ~ptrarray() { delete []v; }

    int num() const { return n; }

    void setsize(int newsize) {
      if (newsize>max) reallocto(newsize);
      if (newsize>n) {
	for (int i=n; i<newsize; i++) v[i] = NULL;
      }
      else {
	// do nothing
      }
      n = newsize;
    }

    T *&operator [] (int ix) const {
      assert(ix>=0 && ix<n);
      return v[ix];
    }

    int add(T *val) {
      int ix = n;
      setsize(n+1);
      v[ix] = val;
      return ix;
    }

    void push(T *val) { add(val); }

    void pop() { setsize(n-1); }
};

#endif
