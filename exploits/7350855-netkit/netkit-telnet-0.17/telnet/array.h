//
// 	File:        array.h
// 	Date:        16-Jul-95
//	Description: array template
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

#ifndef ARRAY_H
#define ARRAY_H

#ifndef assert
#include <assert.h>
#endif

#ifndef NULL
#define NULL 0
#endif

inline void *operator new(size_t, void *v) { return v; }

template <class T>
class array {
  protected:
    T *v;
    int n, max;

    void reallocto(int newsize) {
      while (max<newsize) max += 16;
      char *x = new char[max*sizeof(T)];
      memcpy(x,v,n*sizeof(T));
      delete []((char *)v);
      v = (T *) x;
    }
  public:
    array() { v=NULL; n=max=0; }
    ~array() { setsize(0); delete []((char *)v); }

    int num() const { return n; }

    void setsize(int newsize) {
      if (newsize>max) reallocto(newsize);
      if (newsize>n) {
	// call default constructors
	for (int i=n; i<newsize; i++) (void) new(&v[i]) T;
      }
      else {
	// call destructors
	for (int i=newsize; i<n; i++) v[i].~T();
      }
      n = newsize;
    }

    T &operator [] (int ix) const {
      assert(ix>=0 && ix<n);
      return v[ix];
    }

    int add(const T &val) {
      int ix = n;
      setsize(n+1);
      v[ix] = val;
      return ix;
    }

    void push(const T &val) { add(val); }

    T pop() { T t = (*this)[n-1]; setsize(n-1); return t; }
};

#endif
