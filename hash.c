/*
 * Copyright (c) 2018 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING); if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 ***************************************************************/

#include "inc.h"

/* sha1.c - SHA1 hash function
 * sha256.c - SHA256 hash function
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * Please see below for more legal information!
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/*  Test vectors:
 *
 *  "abc"
 *  A999 3E36 4706 816A BA3E  2571 7850 C26C 9CD0 D89D
 *
 *  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *  8498 3E44 1C3B D26E BAAE  4AA1 F951 29E5 E546 70F1
 */


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#       undef BIG_ENDIAN_HOST
#else
#       define BIG_ENDIAN_HOST 1
#endif

typedef unsigned int u32;
typedef unsigned char byte;

#if defined(__GNUC__) && defined(__i386__)
static inline u32
rol( u32 x, int n)
{
        __asm__("roll %%cl,%0"
                :"=r" (x)
                :"0" (x),"c" (n));
        return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

static void
burn_stack (int bytes)
{
    char buf[128];

    memset (buf, 0, sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        burn_stack (bytes);
}

void
sha1_init( SHA1_CONTEXT *hd )
{
    hd->h0 = 0x67452301;
    hd->h1 = 0xefcdab89;
    hd->h2 = 0x98badcfe;
    hd->h3 = 0x10325476;
    hd->h4 = 0xc3d2e1f0;
    hd->nblocks = 0;
    hd->count = 0;
}


/****************
 * Transform the message X which consists of 16 32-bit-words
 */
static void
sha1_transform( SHA1_CONTEXT *hd, const byte *data )
{
    u32 a,b,c,d,e,tm;
    u32 x[16];

    /* get values from the chaining vars */
    a = hd->h0;
    b = hd->h1;
    c = hd->h2;
    d = hd->h3;
    e = hd->h4;

#ifdef BIG_ENDIAN_HOST
    memcpy( x, data, 64 );
#else
    { int i;
      byte *p2;
      for(i=0, p2=(byte*)x; i < 16; i++, p2 += 4 ) {
	p2[3] = *data++;
	p2[2] = *data++;
	p2[1] = *data++;
	p2[0] = *data++;
      }
    }
#endif


#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )


#define M(i) ( tm =   x[i&0x0f] ^ x[(i-14)&0x0f] \
		    ^ x[(i-8)&0x0f] ^ x[(i-3)&0x0f] \
	       , (x[i&0x0f] = rol(tm,1)) )

#define R(a,b,c,d,e,f,k,m)  do { e += rol( a, 5 )     \
				      + f( b, c, d )  \
				      + k	      \
				      + m;	      \
				 b = rol( b, 30 );    \
			       } while(0)
    R( a, b, c, d, e, F1, K1, x[ 0] );
    R( e, a, b, c, d, F1, K1, x[ 1] );
    R( d, e, a, b, c, F1, K1, x[ 2] );
    R( c, d, e, a, b, F1, K1, x[ 3] );
    R( b, c, d, e, a, F1, K1, x[ 4] );
    R( a, b, c, d, e, F1, K1, x[ 5] );
    R( e, a, b, c, d, F1, K1, x[ 6] );
    R( d, e, a, b, c, F1, K1, x[ 7] );
    R( c, d, e, a, b, F1, K1, x[ 8] );
    R( b, c, d, e, a, F1, K1, x[ 9] );
    R( a, b, c, d, e, F1, K1, x[10] );
    R( e, a, b, c, d, F1, K1, x[11] );
    R( d, e, a, b, c, F1, K1, x[12] );
    R( c, d, e, a, b, F1, K1, x[13] );
    R( b, c, d, e, a, F1, K1, x[14] );
    R( a, b, c, d, e, F1, K1, x[15] );
    R( e, a, b, c, d, F1, K1, M(16) );
    R( d, e, a, b, c, F1, K1, M(17) );
    R( c, d, e, a, b, F1, K1, M(18) );
    R( b, c, d, e, a, F1, K1, M(19) );
    R( a, b, c, d, e, F2, K2, M(20) );
    R( e, a, b, c, d, F2, K2, M(21) );
    R( d, e, a, b, c, F2, K2, M(22) );
    R( c, d, e, a, b, F2, K2, M(23) );
    R( b, c, d, e, a, F2, K2, M(24) );
    R( a, b, c, d, e, F2, K2, M(25) );
    R( e, a, b, c, d, F2, K2, M(26) );
    R( d, e, a, b, c, F2, K2, M(27) );
    R( c, d, e, a, b, F2, K2, M(28) );
    R( b, c, d, e, a, F2, K2, M(29) );
    R( a, b, c, d, e, F2, K2, M(30) );
    R( e, a, b, c, d, F2, K2, M(31) );
    R( d, e, a, b, c, F2, K2, M(32) );
    R( c, d, e, a, b, F2, K2, M(33) );
    R( b, c, d, e, a, F2, K2, M(34) );
    R( a, b, c, d, e, F2, K2, M(35) );
    R( e, a, b, c, d, F2, K2, M(36) );
    R( d, e, a, b, c, F2, K2, M(37) );
    R( c, d, e, a, b, F2, K2, M(38) );
    R( b, c, d, e, a, F2, K2, M(39) );
    R( a, b, c, d, e, F3, K3, M(40) );
    R( e, a, b, c, d, F3, K3, M(41) );
    R( d, e, a, b, c, F3, K3, M(42) );
    R( c, d, e, a, b, F3, K3, M(43) );
    R( b, c, d, e, a, F3, K3, M(44) );
    R( a, b, c, d, e, F3, K3, M(45) );
    R( e, a, b, c, d, F3, K3, M(46) );
    R( d, e, a, b, c, F3, K3, M(47) );
    R( c, d, e, a, b, F3, K3, M(48) );
    R( b, c, d, e, a, F3, K3, M(49) );
    R( a, b, c, d, e, F3, K3, M(50) );
    R( e, a, b, c, d, F3, K3, M(51) );
    R( d, e, a, b, c, F3, K3, M(52) );
    R( c, d, e, a, b, F3, K3, M(53) );
    R( b, c, d, e, a, F3, K3, M(54) );
    R( a, b, c, d, e, F3, K3, M(55) );
    R( e, a, b, c, d, F3, K3, M(56) );
    R( d, e, a, b, c, F3, K3, M(57) );
    R( c, d, e, a, b, F3, K3, M(58) );
    R( b, c, d, e, a, F3, K3, M(59) );
    R( a, b, c, d, e, F4, K4, M(60) );
    R( e, a, b, c, d, F4, K4, M(61) );
    R( d, e, a, b, c, F4, K4, M(62) );
    R( c, d, e, a, b, F4, K4, M(63) );
    R( b, c, d, e, a, F4, K4, M(64) );
    R( a, b, c, d, e, F4, K4, M(65) );
    R( e, a, b, c, d, F4, K4, M(66) );
    R( d, e, a, b, c, F4, K4, M(67) );
    R( c, d, e, a, b, F4, K4, M(68) );
    R( b, c, d, e, a, F4, K4, M(69) );
    R( a, b, c, d, e, F4, K4, M(70) );
    R( e, a, b, c, d, F4, K4, M(71) );
    R( d, e, a, b, c, F4, K4, M(72) );
    R( c, d, e, a, b, F4, K4, M(73) );
    R( b, c, d, e, a, F4, K4, M(74) );
    R( a, b, c, d, e, F4, K4, M(75) );
    R( e, a, b, c, d, F4, K4, M(76) );
    R( d, e, a, b, c, F4, K4, M(77) );
    R( c, d, e, a, b, F4, K4, M(78) );
    R( b, c, d, e, a, F4, K4, M(79) );

    /* update chainig vars */
    hd->h0 += a;
    hd->h1 += b;
    hd->h2 += c;
    hd->h3 += d;
    hd->h4 += e;
}


/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
void
sha1_write( SHA1_CONTEXT *hd, const byte *inbuf, size_t inlen)
{
    if( hd->count == 64 ) { /* flush the buffer */
	sha1_transform( hd, hd->buf );
        burn_stack (88+4*sizeof(void*));
	hd->count = 0;
	hd->nblocks++;
    }
    if( !inbuf )
	return;
    if( hd->count ) {
	for( ; inlen && hd->count < 64; inlen-- )
	    hd->buf[hd->count++] = *inbuf++;
	sha1_write( hd, NULL, 0 );
	if( !inlen )
	    return;
    }

    while( inlen >= 64 ) {
	sha1_transform( hd, inbuf );
	hd->count = 0;
	hd->nblocks++;
	inlen -= 64;
	inbuf += 64;
    }
    burn_stack (88+4*sizeof(void*));
    for( ; inlen && hd->count < 64; inlen-- )
	hd->buf[hd->count++] = *inbuf++;
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */

void
sha1_final(SHA1_CONTEXT *hd)
{
    u32 t, msb, lsb;
    byte *p;

    sha1_write(hd, NULL, 0); /* flush */;

    t = hd->nblocks;
    /* multiply by 64 to make a byte count */
    lsb = t << 6;
    msb = t >> 26;
    /* add the count */
    t = lsb;
    if( (lsb += hd->count) < t )
	msb++;
    /* multiply by 8 to make a bit count */
    t = lsb;
    lsb <<= 3;
    msb <<= 3;
    msb |= t >> 29;

    if( hd->count < 56 ) { /* enough room */
	hd->buf[hd->count++] = 0x80; /* pad */
	while( hd->count < 56 )
	    hd->buf[hd->count++] = 0;  /* pad */
    }
    else { /* need one extra block */
	hd->buf[hd->count++] = 0x80; /* pad character */
	while( hd->count < 64 )
	    hd->buf[hd->count++] = 0;
	sha1_write(hd, NULL, 0);  /* flush */;
	memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
    }
    /* append the 64 bit count */
    hd->buf[56] = msb >> 24;
    hd->buf[57] = msb >> 16;
    hd->buf[58] = msb >>  8;
    hd->buf[59] = msb	   ;
    hd->buf[60] = lsb >> 24;
    hd->buf[61] = lsb >> 16;
    hd->buf[62] = lsb >>  8;
    hd->buf[63] = lsb	   ;
    sha1_transform( hd, hd->buf );
    burn_stack (88+4*sizeof(void*));

    p = hd->buf;
  #ifdef BIG_ENDIAN_HOST
    #define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
  #else /* little endian */
    #define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
		      *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
  #endif
    X(0);
    X(1);
    X(2);
    X(3);
    X(4);
  #undef X

}

byte *
sha1_read( SHA1_CONTEXT *hd )
{
    return hd->buf;
}

/*****************************************************************/
/* sha256                                                        */
/*****************************************************************/

void
sha256_init( SHA256_CONTEXT *hd )
{
    hd->h0 = 0x6a09e667;
    hd->h1 = 0xbb67ae85;
    hd->h2 = 0x3c6ef372;
    hd->h3 = 0xa54ff53a;
    hd->h4 = 0x510e527f;
    hd->h5 = 0x9b05688c;
    hd->h6 = 0x1f83d9ab;
    hd->h7 = 0x5be0cd19;

    hd->nblocks = 0;
    hd->count = 0;
}

/****************
 * Transform the message w which consists of 16 32-bit words
 */
static void
sha256_transform( SHA256_CONTEXT *hd, const byte *data )
{
  u32 a,b,c,d,e,f,g,h;
  u32 w[64];
  int t;
  static const u32 k[]=
    {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

  /* get values from the chaining vars */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

#ifdef BIG_ENDIAN_HOST
  memcpy( w, data, 64 );
#else
  {
    int i;
    byte *p2;

    for(i=0, p2=(byte*)w; i < 16; i++, p2 += 4 )
      {
        p2[3] = *data++;
        p2[2] = *data++;
        p2[1] = *data++;
        p2[0] = *data++;
      }
  }
#endif

#define ROTR(x,n) (((x)>>(n)) | ((x)<<(32-(n))))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sum0(x) (ROTR((x),2) ^ ROTR((x),13) ^ ROTR((x),22))
#define Sum1(x) (ROTR((x),6) ^ ROTR((x),11) ^ ROTR((x),25))
#define S0(x) (ROTR((x),7) ^ ROTR((x),18) ^ ((x)>>3))
#define S1(x) (ROTR((x),17) ^ ROTR((x),19) ^ ((x)>>10))

  for(t=16;t<64;t++)
    w[t] = S1(w[t-2]) + w[t-7] + S0(w[t-15]) + w[t-16];

  for(t=0;t<64;t++)
    {
      u32 t1,t2;

      t1=h+Sum1(e)+Ch(e,f,g)+k[t]+w[t];
      t2=Sum0(a)+Maj(a,b,c);
      h=g;
      g=f;
      f=e;
      e=d+t1;
      d=c;
      c=b;
      b=a;
      a=t1+t2;
      /* printf("t=%d a=%08lX b=%08lX c=%08lX d=%08lX e=%08lX f=%08lX g=%08lX h=%08lX\n",t,a,b,c,d,e,f,g,h); */
    }

#undef ROTR
#undef Ch
#undef Maj
#undef Sum0
#undef Sum1
#undef S0
#undef S1

  /* update chaining vars */
  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;
}

/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
void
sha256_write( SHA256_CONTEXT *hd, const byte *inbuf, size_t inlen)
{
    if( hd->count == 64 ) { /* flush the buffer */
        sha256_transform( hd, hd->buf );
        burn_stack (328);
        hd->count = 0;
        hd->nblocks++;
    }
    if( !inbuf )
        return;
    if( hd->count ) {
        for( ; inlen && hd->count < 64; inlen-- )
            hd->buf[hd->count++] = *inbuf++;
        sha256_write( hd, NULL, 0 );
        if( !inlen )
            return;
    }

    while( inlen >= 64 ) {
        sha256_transform( hd, inbuf );
        hd->count = 0;
        hd->nblocks++;
        inlen -= 64;
        inbuf += 64;
    }
    burn_stack (328);
    for( ; inlen && hd->count < 64; inlen-- )
        hd->buf[hd->count++] = *inbuf++;
}
/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 32 bytes representing the digest.
 */

void
sha256_final(SHA256_CONTEXT *hd)
{
    u32 t, msb, lsb;
    byte *p;

    sha256_write(hd, NULL, 0); /* flush */;

    t = hd->nblocks;
    /* multiply by 64 to make a byte count */
    lsb = t << 6;
    msb = t >> 26;
    /* add the count */
    t = lsb;
    if( (lsb += hd->count) < t )
        msb++;
    /* multiply by 8 to make a bit count */
    t = lsb;
    lsb <<= 3;
    msb <<= 3;
    msb |= t >> 29;

    if( hd->count < 56 ) { /* enough room */
        hd->buf[hd->count++] = 0x80; /* pad */
        while( hd->count < 56 )
            hd->buf[hd->count++] = 0;  /* pad */
    }
    else { /* need one extra block */
        hd->buf[hd->count++] = 0x80; /* pad character */
        while( hd->count < 64 )
            hd->buf[hd->count++] = 0;
        sha256_write(hd, NULL, 0);  /* flush */;
        memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
    }
    /* append the 64 bit count */
    hd->buf[56] = msb >> 24;
    hd->buf[57] = msb >> 16;
    hd->buf[58] = msb >>  8;
    hd->buf[59] = msb      ;
    hd->buf[60] = lsb >> 24;
    hd->buf[61] = lsb >> 16;
    hd->buf[62] = lsb >>  8;
    hd->buf[63] = lsb      ;
    sha256_transform( hd, hd->buf );
    burn_stack (328);

    p = hd->buf;
#ifdef BIG_ENDIAN_HOST
#define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
#else /* little endian */
#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;  \
                      *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
#endif
    X(0);
    X(1);
    X(2);
    X(3);
    X(4);
    X(5);
    X(6);
    X(7);
#undef X
}

byte *
sha256_read( SHA256_CONTEXT *hd )
{
    return hd->buf;
}

/*****************************************************************/
/* sha512                                                        */
/*****************************************************************/

void
sha512_init( SHA512_CONTEXT *hd )
{
    hd->h0 = 0x6a09e667f3bcc908ULL;
    hd->h1 = 0xbb67ae8584caa73bULL;
    hd->h2 = 0x3c6ef372fe94f82bULL;
    hd->h3 = 0xa54ff53a5f1d36f1ULL;
    hd->h4 = 0x510e527fade682d1ULL;
    hd->h5 = 0x9b05688c2b3e6c1fULL;
    hd->h6 = 0x1f83d9abfb41bd6bULL;
    hd->h7 = 0x5be0cd19137e2179ULL;

    hd->nblocks = 0;
    hd->count = 0;
}

/****************
 * Transform the message w which consists of 16 64-bit words
 */
static void
sha512_transform( SHA512_CONTEXT *hd, const byte *data )
{
  u64 a,b,c,d,e,f,g,h;
  u64 w[80];
  int t;
  static const u64 k[]=
    {
      0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
      0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
      0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
      0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
      0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
      0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
      0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
      0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
      0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
      0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
      0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
      0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
      0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
      0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
      0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
      0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
      0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
      0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
      0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
      0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
      0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
      0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
      0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
      0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
      0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
      0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
      0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

  /* get values from the chaining vars */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

#ifdef BIG_ENDIAN_HOST
  memcpy( w, data, 128 );
#else
  {
    int i;
    byte *p2;

    for(i=0, p2=(byte*)w; i < 16; i++, p2 += 8 )
      {
        p2[7] = *data++;
        p2[6] = *data++;
        p2[5] = *data++;
        p2[4] = *data++;
        p2[3] = *data++;
        p2[2] = *data++;
        p2[1] = *data++;
        p2[0] = *data++;
      }
  }
#endif

#define ROTR(x,n) (((x)>>(n)) | ((x)<<(64-(n))))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sum0(x) (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
#define Sum1(x) (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
#define S0(x) (ROTR((x),1) ^ ROTR((x),8) ^ ((x)>>7))
#define S1(x) (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))

  for(t=16;t<80;t++)
    w[t] = S1(w[t-2]) + w[t-7] + S0(w[t-15]) + w[t-16];

  for(t=0;t<80;t++)
    {
      u64 t1,t2;

      t1=h+Sum1(e)+Ch(e,f,g)+k[t]+w[t];
      t2=Sum0(a)+Maj(a,b,c);
      h=g;
      g=f;
      f=e;
      e=d+t1;
      d=c;
      c=b;
      b=a;
      a=t1+t2;
      /* printf("t=%d a=%016llX b=%016llX c=%016llX d=%016llX e=%016llX f=%016llX g=%016llX h=%016llX\n",t,a,b,c,d,e,f,g,h); */
    }

#undef ROTR
#undef Ch
#undef Maj
#undef Sum0
#undef Sum1
#undef S0
#undef S1

  /* update chaining vars */
  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;
}

/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
void
sha512_write( SHA512_CONTEXT *hd, const byte *inbuf, size_t inlen)
{
    if( hd->count == 128 ) { /* flush the buffer */
        sha512_transform( hd, hd->buf );
        burn_stack (768);
        hd->count = 0;
        hd->nblocks++;
    }
    if( !inbuf )
        return;
    if( hd->count ) {
        for( ; inlen && hd->count < 128; inlen-- )
            hd->buf[hd->count++] = *inbuf++;
        sha512_write( hd, NULL, 0 );
        if( !inlen )
            return;
    }

    while( inlen >= 128 ) {
        sha512_transform( hd, inbuf );
        hd->count = 0;
        hd->nblocks++;
        inlen -= 128;
        inbuf += 128;
    }
    burn_stack (768);
    for( ; inlen && hd->count < 128; inlen-- )
        hd->buf[hd->count++] = *inbuf++;
}
/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 64 bytes representing the digest.
 */

void
sha512_final(SHA512_CONTEXT *hd)
{
    u64 t, msb, lsb;
    byte *p;

    sha512_write(hd, NULL, 0); /* flush */;

    t = hd->nblocks;
    /* multiply by 128 to make a byte count */
    lsb = t << 7;
    msb = t >> 57;
    /* add the count */
    t = lsb;
    if( (lsb += hd->count) < t )
        msb++;
    /* multiply by 8 to make a bit count */
    t = lsb;
    lsb <<= 3;
    msb <<= 3;
    msb |= t >> 61;

    if( hd->count < 112 ) { /* enough room */
        hd->buf[hd->count++] = 0x80; /* pad */
        while( hd->count < 112 )
            hd->buf[hd->count++] = 0;  /* pad */
    }
    else { /* need one extra block */
        hd->buf[hd->count++] = 0x80; /* pad character */
        while( hd->count < 128 )
            hd->buf[hd->count++] = 0;
        sha512_write(hd, NULL, 0);  /* flush */;
        memset(hd->buf, 0, 112 ); /* fill next block with zeroes */
    }
    /* append the 128 bit count */
    hd->buf[112] = msb >> 56;
    hd->buf[113] = msb >> 48;
    hd->buf[114] = msb >> 40;
    hd->buf[115] = msb >> 32;
    hd->buf[116] = msb >> 24;
    hd->buf[117] = msb >> 16;
    hd->buf[118] = msb >> 8;
    hd->buf[119] = msb;

    hd->buf[120] = lsb >> 56;
    hd->buf[121] = lsb >> 48;
    hd->buf[122] = lsb >> 40;
    hd->buf[123] = lsb >> 32;
    hd->buf[124] = lsb >> 24;
    hd->buf[125] = lsb >> 16;
    hd->buf[126] = lsb >> 8;
    hd->buf[127] = lsb;

    sha512_transform( hd, hd->buf );
    burn_stack (768);

    p = hd->buf;
#ifdef BIG_ENDIAN_HOST
#define X(a) do { *(u64*)p = hd->h##a ; p += 8; } while (0)
#else /* little endian */
#define X(a) do { *p++ = hd->h##a >> 56; *p++ = hd->h##a >> 48;       \
                  *p++ = hd->h##a >> 40; *p++ = hd->h##a >> 32;       \
                  *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;       \
                  *p++ = hd->h##a >> 8;  *p++ = hd->h##a; } while (0)
#endif
    X (0);
    X (1);
    X (2);
    X (3);
    X (4);
    X (5);
    /* Note that these last two chunks are included even for SHA384.
       We just ignore them. */
    X (6);
    X (7);
#undef X
}

byte *
sha512_read( SHA512_CONTEXT *hd )
{
    return hd->buf;
}


/*****************************************************************/

static void rpmMD5Transform(u32 buf[4], u32 const in[16]);

#ifdef BIG_ENDIAN_HOST
static void byteReverse(unsigned char *buf, unsigned longs)
{
    u32 t;
    do {
        t = ((unsigned) buf[3] << 8 | buf[2]) << 16 |
            ((unsigned) buf[1] << 8 | buf[0]);
        *(u32 *) buf = t;
        buf += 4;
    } while (--longs);
}
#endif

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void md5_init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;
    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

void md5_write(struct MD5Context *ctx, byte const *buf, u32 len)
{
    u32 t;

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + (len << 3)) < t)
        ctx->bits[1]++;         /* Carry from low to high */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;        /* Bytes already in shsInfo->data */
    if (t) {
        unsigned char *p = (unsigned char *) ctx->in + t;

        t = 64 - t;
        if (len < t) {
            memcpy(p, buf, len);
            return;
        }
        memcpy(p, buf, t);
#ifdef BIG_ENDIAN_HOST
	byteReverse(ctx->in, 16);
#endif
        rpmMD5Transform(ctx->buf, (u32 *) ctx->in);
        buf += t;
        len -= t;
    }
    while (len >= 64) {
        memcpy(ctx->in, buf, 64);
#ifdef BIG_ENDIAN_HOST
	byteReverse(ctx->in, 16);
#endif
        rpmMD5Transform(ctx->buf, (u32 *) ctx->in);
        buf += 64;
        len -= 64;
    }
    memcpy(ctx->in, buf, len);
}

void md5_final(byte *digest, struct MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(p, 0, count);
#ifdef BIG_ENDIAN_HOST
	byteReverse(ctx->in, 16);
#endif
        rpmMD5Transform(ctx->buf, (u32 *) ctx->in);

        /* Now fill the next block with 56 bytes */
        memset(ctx->in, 0, 56);
    } else {
        /* Pad block to 56 bytes */
        memset(p, 0, count - 8);
    }
#ifdef BIG_ENDIAN_HOST
    byteReverse(ctx->in, 14);
#endif

    /* Append length in bits and transform */
    ((u32 *) ctx->in)[14] = ctx->bits[0];
    ((u32 *) ctx->in)[15] = ctx->bits[1];

    rpmMD5Transform(ctx->buf, (u32 *) ctx->in);
#ifdef BIG_ENDIAN_HOST
    byteReverse((unsigned char *) ctx->buf, 4);
#endif
    memcpy(digest, ctx->buf, 16);
    memset(ctx, 0, sizeof(*ctx));        /* In case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */
#undef F1
#undef F2
#undef F3
#undef F4

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  md5_write blocks
 * the data and converts bytes into longwords for this routine.
 */
static void rpmMD5Transform(u32 buf[4], u32 const in[16])
{
    register u32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}


void hash_init(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    sha1_init(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    sha256_init(&c->sha256);
  else if (hashalgo == HASH_SHA512)
    sha512_init(&c->sha512);
}

void hash_write(HASH_CONTEXT *c, const unsigned char *b, size_t l)
{
  if (hashalgo == HASH_SHA1)
    sha1_write(&c->sha1, b, l);
  else if (hashalgo == HASH_SHA256)
    sha256_write(&c->sha256, b, l);
  else if (hashalgo == HASH_SHA512)
    sha512_write(&c->sha512, b, l);
}

void hash_final(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    sha1_final(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    sha256_final(&c->sha256);
  else if (hashalgo == HASH_SHA512)
    sha512_final(&c->sha512);
}

unsigned char *hash_read(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    return sha1_read(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    return sha256_read(&c->sha256);
  else if (hashalgo == HASH_SHA512)
    return sha512_read(&c->sha512);
  return 0;
}

int hash_len()
{
  if (hashalgo == HASH_SHA1)
    return 20;
  else if (hashalgo == HASH_SHA256)
    return 32;
  else if (hashalgo == HASH_SHA512)
    return 64;
  return 0;
}

