/*
 * Copyright (c) 2006-2013 Michael Schroeder, Novell Inc.
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

#define MYPORT 5167

static char *host;
static char *user;
static char *algouser;
static int port = MYPORT;

#define HEADER_SIGNATURES 62
#define RPMSIGTAG_DSA   267		/* header only sig */
#define RPMSIGTAG_RSA   268		/* header only sig */
#define RPMSIGTAG_SHA1  269		/* header only hash */
#define RPMSIGTAG_SIZE 1000
#define RPMSIGTAG_PGP  1002
#define RPMSIGTAG_MD5  1004
#define RPMSIGTAG_GPG  1005

#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#	undef BIG_ENDIAN_HOST
#else
#	define BIG_ENDIAN_HOST 1
#endif


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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>


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

typedef struct {
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buf[64];
    int  count;
} SHA1_CONTEXT;

static void
burn_stack (int bytes)
{
    char buf[128];

    memset (buf, 0, sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        burn_stack (bytes);
}

static void
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
static void
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

static void
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

static byte *
sha1_read( SHA1_CONTEXT *hd )
{
    return hd->buf;
}

/*****************************************************************/

typedef struct {
    u32  h0,h1,h2,h3,h4,h5,h6,h7;
    u32  nblocks;
    byte buf[64];
    int  count;
} SHA256_CONTEXT;

static void
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
      /* printf("t=%d a=%08lX b=%08lX c=%08lX d=%08lX e=%08lX f=%08lX g=%08lX h=
%08lX\n",t,a,b,c,d,e,f,g,h); */
    }

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
static void
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

static void
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

static byte *
sha256_read( SHA256_CONTEXT *hd )
{
    return hd->buf;
}


/*****************************************************************/

struct MD5Context {
        u32 buf[4];
        u32 bits[2];
        byte in[64];
};

typedef struct MD5Context MD5_CTX;
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
static void md5_init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;
    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

static void md5_write(struct MD5Context *ctx, byte const *buf, u32 len)
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

static void md5_final(byte *digest, struct MD5Context *ctx)
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



/*****************************************************************/



#define CRCINIT 0xb704ce
#define CRCPOLY 0x864cfb


static u32
crc24(const byte *octets, int len)
{
  u32 crc = CRCINIT;
  int i;

  while (len-- > 0) {
    crc ^= (*octets++) << 16;
    for (i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000)
	crc ^= CRCPOLY;
    }
  }
  return crc & 0xffffff;
}

static void
printr64(FILE *f, const byte *str, int len)
{
  int a, b, c, i;
  static const byte bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  i = -1;
  while (len > 0)
    {
      if (++i == 16)
	{
	  i = 0;
	  putc('\n', f);
	}
      a = *str++;
      b = --len > 0 ? *str++ : 0;
      c = --len > 0 ? *str++ : 0;
      --len;
      putc(bintoasc[a >> 2], f);
      putc(bintoasc[(a & 3) << 4 | b >> 4], f);
      putc(len > -2 ? bintoasc[(b & 15) << 2 | c >> 6] : '=', f);
      putc(len > -1 ? bintoasc[c & 63] : '=', f);
    }
    putc('\n', f);
}

static const char *armor_signature_header = "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v1.0.7 (GNU/Linux)\n\n";
static const char *armor_signature_footer = "-----END PGP SIGNATURE-----\n";

void
write_armored_signature(FILE *fp, byte *signature, int length)
{
  u32 crc;
  byte hash[5];

  fprintf(fp, "%s", armor_signature_header);
  printr64(fp, signature, length);
  crc = crc24(signature, length);
  hash[0] = crc >> 16;
  hash[1] = crc >> 8;
  hash[2] = crc;
  putc('=', fp);
  printr64(fp, hash, 3);
  fprintf(fp, "%s", armor_signature_footer);
}

char *
get_armored_signature(byte *signature, int length)
{
  char *ret = 0;
  size_t size;
  FILE *fp = open_memstream(&ret, &size);
  write_armored_signature(fp, signature, length);
  fclose(fp);
  return ret;
}

static ssize_t xread(int fd, void *buf, size_t count)
{
  ssize_t r, r2;
  r2 = 0;
  while(count)
    {
      r = read(fd, buf, count);
      if (r <= 0)
	return r2 ? r2 : r;
      count -= r;
      buf += r;
      r2 += r;
    }
  return r2;
}

static ssize_t xwrite(int fd, const void *buf, size_t count)
{
  ssize_t r, r2;
  r2 = 0;
  while(count)
    {
      r = write(fd, buf, count);
      if (r < 0)
	{
	  perror("write");
	  exit(1);
	}
      count -= r;
      buf += r;
      r2 += r;
    }
  return r2;
}

static uid_t uid;

static int opensocket(void)
{
  static int hostknown;
  static struct sockaddr_in svt;
  int sock;
  int optval;

  if (!hostknown)
    {
      svt.sin_addr.s_addr = inet_addr(host);
      svt.sin_family = AF_INET;
      if (svt.sin_addr.s_addr == -1)
	{
	  struct hostent *hp;
	  if (!(hp = gethostbyname(host)))
	    {
	      printf("%s: unknown host\n", host);
	      exit(1);
	    }
	  memmove(&svt.sin_addr, hp->h_addr, hp->h_length);
	  svt.sin_family = hp->h_addrtype;
	}
      svt.sin_port = htons(port);
      hostknown = 1;
    }
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      perror("socket");
      exit(1);
    }
  if (uid)
    seteuid(0);
  for (;;)
    {
      if (!bindresvport(sock, NULL))
	break;
      if (errno != EADDRINUSE)
	{
	  perror("bindresvport");
	  exit(1);
	}
      sleep(1);
    }
  if (uid)
    {
      if (seteuid(uid))
	{
	  perror("seteuid");
	  exit(1);
	}
    }
  if (connect(sock, (struct sockaddr *)&svt, sizeof(svt)))
    {
      perror(host);
      exit(1);
    }
  optval = 1;
  setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
  return sock;
}

static int verbose;

#define HASH_SHA1	0
#define HASH_SHA256	1

#define PUB_DSA         0
#define PUB_RSA         1

static const char *const pubname[] = {"DSA", "RSA"};
static const char *const hashname[] = {"SHA1", "SHA256"};
static const int  hashlen[] = {20, 32};

/* PGP constants */
static const int  hashpgpalgo[] = {2, 8};
static const int  pubpgpalgo[] = {17, 1};

/* RPM constants */
static const int  pubtag[]  = { RPMSIGTAG_GPG, RPMSIGTAG_PGP };
static const int  pubtagh[] = { RPMSIGTAG_DSA, RPMSIGTAG_RSA };	/* header only tags */

static int hashalgo = HASH_SHA1;
static const char *timearg;
static char *privkey;
static int privkey_read;
static int noheaderonly;
static int pkcs1pss;
static char *chksumfile;
static int chksumfilefd = -1;
static int dov4sig;
static int pubalgoprobe = -1;

typedef union {
  SHA1_CONTEXT sha1;
  SHA256_CONTEXT sha256;
} HASH_CONTEXT;

static void hash_init(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    sha1_init(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    sha256_init(&c->sha256);
}

static void hash_write(HASH_CONTEXT *c, const unsigned char *b, size_t l)
{
  if (hashalgo == HASH_SHA1)
    sha1_write(&c->sha1, b, l);
  else if (hashalgo == HASH_SHA256)
    sha256_write(&c->sha256, b, l);
}

static void hash_final(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    sha1_final(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    sha256_final(&c->sha256);
}

static unsigned char *hash_read(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    return sha1_read(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    return sha256_read(&c->sha256);
  return 0;
}

#define MODE_UNSET        0
#define MODE_RPMSIGN      1
#define MODE_CLEARSIGN    2
#define MODE_DETACHEDSIGN 3
#define MODE_KEYID        4
#define MODE_PUBKEY       5
#define MODE_KEYGEN       6
#define MODE_KEYEXTEND    7
#define MODE_RAWDETACHEDSIGN 8
#define MODE_RAWOPENSSLSIGN 9
#define MODE_CREATECERT   10
#define MODE_APPIMAGESIGN 11

static const char *const modes[] = {
  "?", "rpm sign", "clear sign", "detached sign", "keyid", "pubkey", "keygen", "keyextend",
  "raw detached sign" "raw openssl sign" "cert create", "appimage sign"
};

static void
readprivkey(void)
{
  FILE *fp;
  int l, ll;
  if (privkey_read)
    return;
  if ((fp = fopen(privkey, "r")) == 0)
    {
      perror(privkey);
      exit(1);
    }
  privkey_read = 1;
  privkey = malloc(8192);
  *privkey = 0;
  l = 0;
  while (l < 8192 && (ll = fread(privkey + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 0)
    {
      fprintf(stderr, "empty private\n");
      exit(1);
    }
  if (l == 8192)
    {
      fprintf(stderr, "private key too large\n");
      exit(1);
    }
  if (privkey[l - 1] == '\n')
    l--;
  privkey[l] = 0;
}

static int
doreq_old(int sock, byte *buf, int inbufl, int bufl)
{
  int l, outl, errl;

  if (write(sock, buf, inbufl) != inbufl)
    {
      perror("write");
      close(sock);
      return -1;
    }

  l = 0; 
  for (;;) 
    {
      int ll;
      if (l == bufl)
	{
	  fprintf(stderr, "packet too big\n");
	  close(sock);
	  return -1;
	}
      ll = read(sock, buf + l, bufl - l);
      if (ll == -1)
	{
	  perror("read");
	  close(sock);
	  return -1;
	}
      if (ll == 0)
	break;
      l += ll;
    }
  close(sock);
  if (l < 6)
    {
      fprintf(stderr, "packet too small\n");
      return -1;
    }
  outl = buf[2] << 8 | buf[3];
  errl = buf[4] << 8 | buf[5];
  if (l != outl + errl + 6)
    {
      fprintf(stderr, "packet size mismatch %d %d %d\n", l, outl, errl);
      return -1;
    }
  if (errl)
    fwrite(buf + 6 + outl, 1, errl, stderr);
  if (buf[0] << 8 | buf[1])
    return -(buf[0] << 8 | buf[1]);
  memmove(buf, buf + 6, outl);
  return outl;
}

static int
doreq(int sock, int argc, const char **argv, byte *buf, int bufl, int nret)
{
  byte *bp;
  int i, l, v, outl;

  bp = buf + 2;
  *bp++ = 0;
  *bp++ = 0;
  *bp++ = argc >> 8;
  *bp++ = argc & 255;
  for (i = 0; i < argc; i++)
    {
      v = strlen(argv[i]);
      *bp++ = v >> 8;
      *bp++ = v & 255;
    }
  for (i = 0; i < argc; i++)
    {
      v = strlen(argv[i]);
      if (bp + v > buf + bufl)
	{
	  fprintf(stderr, "request buffer overflow\n");
	  close(sock);
	  return -1;
	}
      memcpy(bp, argv[i], v);
      bp += v;
    }
  v = bp - (buf + 4);
  buf[0] = v >> 8;
  buf[1] = v & 255;

  outl = doreq_old(sock, buf, (int)(bp - buf), bufl);
  if (outl < 0)
    return outl;

  if (nret)
    {
      /* verify returned data */
      if (outl < 2 + 2 * nret)
	{
	  fprintf(stderr, "answer too small\n");
	  return -1;
	}
      if (buf[0] != 0 || buf[1] != nret)
	{
	  fprintf(stderr, "bad return count\n");
	  return -1;
	}
      l = 2;
      for (i = 0; i < nret; i++)
	l += 2 + (buf[2 + i * 2] << 8 | buf[2 + i * 2 + 1]);
      if (l != outl)
	{
	  fprintf(stderr, "answer size mismatch\n");
	  return -1;
	}
    }
  return outl;
}


static inline int
getu8(const byte *p)
{
  return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline int
getu8c(const byte *p)
{
  if (p[0])
    {
      fprintf(stderr, "header data overflow\n");
      exit(1);
    }
  return p[1] << 16 | p[2] << 8 | p[3];
}

static byte *
findmax(byte *rpmsig, int rpmsigcnt, int targetoff)
{
  int i;
  byte *rsp;
  int maxoff;
  byte *maxrsp;

  maxoff = -1;
  maxrsp = 0;
  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      int off = getu8c(rsp + 8);
      if (off >= targetoff || off < maxoff)
	continue;
      maxoff = off;
      maxrsp = rsp;
    }
  return maxrsp;
}

static int
datalen(byte *rpmsig, int rpmsigcnt, byte *rsp)
{
  int type, cnt;

  type = getu8c(rsp + 4);
  cnt = getu8c(rsp + 12);
  if (type == 6 || type == 8 || type == 9)
    {
      int i = 0;
      int off = getu8c(rsp + 8);
      if (type == 6)
	cnt = 1;
      while (cnt-- > 0)
	{
	  while (rpmsig[rpmsigcnt * 16 + off + i])
	    i++;
	  i++;	/* count termination 0 */
	}
      return i;
    }
  if (type == 3)
    return 2 * cnt;
  else if (type == 4)
    return 4 * cnt;
  else if (type == 5)
    return 8 * cnt;
  return cnt;
}

static int
sigtopubalgo(byte *buf, int outl)
{
  int o;
  if (outl < 2)
    return -1;
  if (buf[0] == 0x88)
    o = 2;
  else if (buf[0] == 0x89)
    o = 3;
  else if (buf[0] == 0x8a)
    o = 5;
  else
    return -1;
  if (o >= outl)
    return -1;
  if (buf[o] == 3)
    o += 15;
  else if (buf[o] == 4)
    o += 2;
  else
    return -1;
  if (o >= outl)
    return -1;
  if (buf[o] == 1)
    return PUB_RSA;
  if (buf[o] == 17)
    return PUB_DSA;
  return -1;
}

static int
findsigoff(byte *buf, int outl)
{
  int o;
  if (outl < 2)
    return -1;
  if (buf[0] == 0x88)
    o = 2;
  else if (buf[0] == 0x89)
    o = 3;
  else if (buf[0] == 0x8a)
    o = 5;
  else
    return -1;
  if (o >= outl)
    return -1;
  if (buf[o] == 3)
    o += 19;
  else if (buf[o] == 4)
    {
      o += 4;
      if (o + 1 >= outl)
        return -1;
      o += 2 + (buf[o] << 8) + buf[o];
      if (o + 1 >= outl)
        return -1;
      o += 2 + (buf[o] << 8) + buf[o];
      o += 2;
    }
  else
    return -1;
  if (o >= outl)
    return -1;
  return o;
}

static inline int
elf16(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8;
  return buf[0] << 8 | buf[1];
}

static inline unsigned int
elf32(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

static inline unsigned int
elf64(unsigned char *buf, int le, int is64)
{
  if (is64)
    {
      buf += le ? 4 : 0;
      if (buf[0] || buf[1] || buf[2] || buf[3])
        return ~0;
      buf += le ? -4 : 4;
    }
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

void
perror_exit(const char *s)
{
  perror(s);
  exit(1);
}


void
write_appimage_signature(char *filename, byte *signature, int length)
{
  // find .sha256_sig section offset in ELF file
  unsigned char elfbuf[128];

  int le, is64;
  off_t soff;
  int snum, ssiz;
  int i, l, stridx;
  FILE *fp;
  char *armored_signature;
  size_t siglen;
  unsigned int sha256_sig_offset = 0;
  unsigned int sha256_sig_size = 0;
  unsigned char *sects, *strsect;
  unsigned int slen;
  unsigned int o;

  if ((fp = fopen(filename, "r+")) == 0)
    perror_exit(filename);
  l = fread(elfbuf, 1, 128, fp);
  if (l < 128)
    perror_exit("offset 1");
  if (elfbuf[0] != 0x7f || elfbuf[1] != 'E' || elfbuf[2] != 'L' || elfbuf[3] != 'F')
    perror_exit("offset 2");
  is64 = elfbuf[4] == 2;
  le = elfbuf[5] != 2;
  if (is64 && l < 0x40)
    perror_exit("offset 3");
  soff = elf64(is64 ? elfbuf + 40 : elfbuf + 32, le, is64);
  if (soff == (off_t)~0)
    perror_exit("offset 4");
  ssiz = elf16(elfbuf + (is64 ? 0x40 - 6 : 0x34 - 6), le);
  if (ssiz < (is64 ? 64 : 40) || ssiz >= 32768)
    perror_exit("offset 5");
  snum = elf16(elfbuf + (is64 ? 0x40 - 4 : 0x34 - 4), le);
  stridx = elf16(elfbuf + (is64 ? 0x40 - 2 : 0x34 - 2), le);
  if (stridx >= snum)
    perror_exit("offset 6");
  sects = malloc(snum * ssiz);
  if (!sects)
    perror_exit("offset 7");
  if (fseek(fp, soff, SEEK_SET) != 0 || fread(sects, 1, snum * ssiz, fp) != snum * ssiz)
    {
      free(sects);
      perror_exit("offset");
    }
  strsect = sects + stridx * ssiz;
  if (elf32(strsect + 4, le) != 3)
    {
      free(sects);
      perror_exit("offset");
    }
  soff = elf64(is64 ? strsect + 24 : strsect + 16, le, is64);
  slen = elf64(is64 ? strsect + 32 : strsect + 20, le, is64);
  if (soff == (off_t)~0 || slen == ~0 || (int)slen < 0)
    {
      free(sects);
      perror_exit("offset");
    }
  strsect = malloc(slen);
  if (!strsect)
    {
      free(sects);
      perror_exit("offset");
    }
  if (fseek(fp, soff, SEEK_SET) != 0 || fread(strsect, 1, slen, fp) != slen)
    {
      free(sects);
      free(strsect);
      perror_exit("offset");
    }
  for (i = 0; i < snum; i++)
    {
      o = elf32(sects + i * ssiz, le);
      if (o > slen)
        continue;
      // printf("sect #%d %s (o=%d)\n", i, strsect + o, o);
  
      if (o + 11 <= slen && memcmp(strsect + o, ".sha256_sig", 11) == 0) {
        unsigned int sh_offset = i * ssiz + (is64 ? 24 : 16);
        sha256_sig_offset = elf64(sects + sh_offset, le, is64);
        sha256_sig_size = elf64(sects + sh_offset + (is64 ? 8 : 4), le, is64);
        break;
      }
    }
  free(strsect);
  free(sects);

  if (sha256_sig_offset == 0)
    perror_exit(".sha256_sig not found");

  armored_signature = get_armored_signature(signature, length);
  siglen = strlen(armored_signature) + 1;
  if (siglen > sha256_sig_size)
    perror_exit("section too small for signature");

  if (fseek(fp, sha256_sig_offset, SEEK_SET) == (off_t)-1)
    perror_exit("lseek");
  if (fwrite(armored_signature, siglen, 1, fp) != 1)
    perror_exit("signature write");
  for(; siglen < sha256_sig_size; siglen++)
    fputc(0x0, fp);
  if (fclose(fp))
    perror_exit("fclose error");
}

static int
rpminsertsig(byte *rpmsig, int *rpmsigsizep, int *rpmsigcntp, int *rpmsigdlenp, const int *sigtags, byte *newsig, int newsiglen)
{
  int rpmsigsize, rpmsigcnt, rpmsigdlen;
  int i, myi, tag, off;
  byte *rsp;
  u32 before;
  int pad;
  byte *region = 0;
  int pubalgo, sigtag;

  rpmsigsize = *rpmsigsizep;
  rpmsigcnt = *rpmsigcntp;
  rpmsigdlen = *rpmsigdlenp;

  if (newsiglen > 1024)
    {
      fprintf(stderr, "signature too big: %d\n", newsiglen);
      return -1;
    }
  pubalgo = sigtopubalgo(newsig, newsiglen);
  if (pubalgo < 0)
    {
      fprintf(stderr, "signature has unknown pubkey algorithm\n");
      return -1;
    }
  sigtag = sigtags[pubalgo];

  // first some sanity checking
  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      off = getu8c(rsp + 8);
      if (off < 0 || off > rpmsigdlen)
	{
	  fprintf(stderr, "data offset out of range\n");
	  exit(1);
	}
    }

  // now find the correct place to insert the signature
  for (i = 0, tag = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      tag = getu8(rsp);
      // fprintf(stderr, "tag %d\n", tag);
      if (i == 0 && tag >= 61 && tag < 64)
	region = rsp;
      if (tag >= sigtag)
	break;
    }
  // fprintf(stderr, "inserting at position %d of %d\n", i, rpmsigcnt);
  if (i < rpmsigcnt && tag == sigtag)
    abort();

  // insert it
  memmove(rsp + 16, rsp, rpmsigsize - i * 16);
  memset(rsp, 0, 16);
  rsp[2] = sigtag >> 8;
  rsp[3] = sigtag & 0xff;
  rsp[7] = 7;
  rsp[14] = newsiglen >> 8;
  rsp[15] = newsiglen & 0xff;

  if (i < rpmsigcnt)
    before = getu8c(rsp + 16 + 8);
  else if (region)
    before = getu8c(region + 8);
  else
    before = rpmsigdlen;
  if (before > rpmsigdlen)
    {
      fprintf(stderr, "sig data range error\n");
      return -1;
    }

  // fprintf(stderr, "before=%d sigdlen=%d\n", before, rpmsigdlen);
  rpmsigcnt++;
  if (before < rpmsigdlen)
    memmove(rpmsig + rpmsigcnt * 16 + before + newsiglen, rpmsig + rpmsigcnt * 16 + before, rpmsigdlen - before);
  memmove(rpmsig + rpmsigcnt * 16 + before, newsig, newsiglen);
  rsp[8] = before >> 24;
  rsp[9] = before >> 16;
  rsp[10] = before >> 8;
  rsp[11] = before;
  rpmsigdlen += newsiglen;

  // now fix up all entries behind us
  myi = i;
  rsp = rpmsig;
  for (i = 0; i < rpmsigcnt; i++, rsp += 16)
    {
      if (i == myi)
	continue;
      off = getu8c(rsp + 8);
      if (off < before)
	continue;
      off += newsiglen;
      rsp[8] = off >> 24;
      rsp[9] = off >> 16;
      rsp[10] = off >> 8;
      rsp[11] = off;
    }

  // correct the padding of all entries
  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      int align, off2, type, lastoff;
      byte *lastrsp;

      type = getu8c(rsp + 4);
      if (type == 3)
	align = 2;
      else if (type == 4)
	align = 4;
      else if (type == 5)
	align = 8;
      else
	align = 1;
      off = getu8c(rsp + 8);
      if (off == 0)
	continue;
      /* find end of last data */
      lastrsp = findmax(rpmsig, rpmsigcnt, off);
      if (!lastrsp)
	continue;
      lastoff = getu8c(lastrsp + 8);
      lastoff += datalen(rpmsig, rpmsigcnt, lastrsp);
      if (lastoff > off)
	{
	  fprintf(stderr, "lastoff error %d %d\n", lastoff, off);
	  return -1;
	}
      if (align > 1 && (lastoff % align) != 0)
	lastoff += align - (lastoff % align);
      if (off == lastoff)
	continue;
      /* now move over from off to lastoff */
      memmove(rpmsig + rpmsigcnt * 16 + lastoff, rpmsig + rpmsigcnt * 16 + off, rpmsigdlen - off);
      rpmsigdlen += lastoff - off;
      if (lastoff > off)
	memset(rpmsig + rpmsigcnt * 16 + off, 0, lastoff - off);
      /* fix up all offsets */
      for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
	{
	  off2 = getu8c(rsp + 8);
	  if (off2 < off)
	    continue;
	  off2 += lastoff - off;
	  rsp[8] = off2 >> 24;
	  rsp[9] = off2 >> 16;
	  rsp[10] = off2 >> 8;
	  rsp[11] = off2;
	}
      /* start over */
      i = -1;
      rsp = rpmsig - 16;
    }

  // correct region count
  if (region)
    {
      if (getu8(region + 12) != 16)
	{
	  fprintf(stderr, "bad region in signature\n");
	  return -1;
	}
      off = getu8c(region + 8);
      rsp = rpmsig + rpmsigcnt * 16 + off;
      tag = getu8(rsp + 8);
      if (-tag != (rpmsigcnt - 1) * 16)
	{
	  fprintf(stderr, "bad region data in signature (%d)\n", -tag);
	  return -1;
	}
      tag -= 16;
      rsp[8] = tag >> 24;
      rsp[9] = tag >> 16;
      rsp[10] = tag >> 8;
      rsp[11] = tag;
    }

  // align to multiple of 8
  pad = 7 - ((rpmsigdlen + 7) & 7);
  if (pad)
    memset(rpmsig + rpmsigcnt * 16 + rpmsigdlen, 0, pad);
  rpmsigsize = rpmsigcnt * 16 + rpmsigdlen + pad;

  *rpmsigsizep = rpmsigsize;
  *rpmsigcntp = rpmsigcnt;
  *rpmsigdlenp = rpmsigdlen;
  return 0;
}

static unsigned char
v4sig_skel[] = {
  0x04,		/* version */
  0x00, 	/* type */
  0x00,		/* pubalgo */
  0x00,		/* hashalgo */
  0x00, 0x06, 	/* octet count hashed */
  0x05, 0x02, 0x00, 0x00, 0x00, 0x00,	/* sig created subpkg */
  0x00, 0x0a, 	/* octet count unhashed */
  0x09, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* issuer subpkg */
};

#define V4SIG_HASHED (4 + 2 + 6)

static unsigned char *
genv4sigtrail(int mode, int pubalgo, int hashalgo, u32 signtime, int *v4sigtraillen)
{
  unsigned char *v4sigtrail = malloc(V4SIG_HASHED + 6);
  memcpy(v4sigtrail, v4sig_skel, V4SIG_HASHED);
  v4sigtrail[1] = mode == MODE_CLEARSIGN ? 0x01 : 0x00;
  v4sigtrail[2] = pubpgpalgo[pubalgo];
  v4sigtrail[3] = hashpgpalgo[hashalgo];
  v4sigtrail[8] = signtime >> 24;
  v4sigtrail[9] = signtime >> 16;
  v4sigtrail[10] = signtime >> 8;
  v4sigtrail[11] = signtime;
  v4sigtrail[V4SIG_HASHED] = 4;
  v4sigtrail[V4SIG_HASHED + 1] = 255;
  v4sigtrail[V4SIG_HASHED + 2] = 0;
  v4sigtrail[V4SIG_HASHED + 3] = 0;
  v4sigtrail[V4SIG_HASHED + 4] = V4SIG_HASHED >> 8;
  v4sigtrail[V4SIG_HASHED + 5] = V4SIG_HASHED;
  *v4sigtraillen = V4SIG_HASHED + 6;
  return v4sigtrail;
}

static int
v3tov4(unsigned char *v4sigtrail, unsigned char *v3sig, int v3siglen, int tail, int left)
{
  int o;
  int l, nl;
  int nhl;
  unsigned char issuer[8];

  if (v3siglen < 17)
    {
      fprintf(stderr, "v3 signature too short\n");
      exit(1);
    }
  if (v3sig[0] == 0x88)
    o = 2;
  else if (v3sig[0] == 0x89)
    o = 3;
  else if (v3sig[0] == 0x8a)
    o = 5;
  else
    {
      fprintf(stderr, "bad answer package: %02x\n", v3sig[0]);
      exit(1);
    }
  if (v3sig[o] == 4)
    return v3siglen;	/* already version 4 */

  /* check that everything matches */
  if (v3sig[o] != 3)
    {
      fprintf(stderr, "v3tov4: not a v3 sig\n");
      exit(1);
    }
  if (v3sig[o + 2] != v4sigtrail[1])
    {
      fprintf(stderr, "v3tov4 type mismatch\n");
      exit(1);
    }
  if (memcmp(v3sig + o + 3, v4sigtrail + 8, 4))
    {
      fprintf(stderr, "v3tov4 creation time mismatch\n");
      exit(1);
    }
  if (v3sig[o + 15] != v4sigtrail[2])
    {
      fprintf(stderr, "v3tov4 pubkey algo mismatch: %d %d\n", v3sig[o + 15], v4sigtrail[2]);
      exit(1);
    }
  if (v3sig[o + 16] != v4sigtrail[3])
    {
      fprintf(stderr, "v3tov4 hash algo mismatch\n");
      exit(1);
    }

  /* stash issuer away */
  memcpy(issuer, v3sig + o + 7, 8);

  l = v3siglen - (o + 17);	/* signature stuff */
  if (l < 2)
    {
      fprintf(stderr, "v3 signature too short\n");
      exit(1);
    }
  /* make room */
  memmove(v3sig + left, v3sig, v3siglen + tail);
  nl = l + sizeof(v4sig_skel);
  if (nl < 256)
    {
      v3sig[0] = 0x88;
      v3sig[1] = nl;
      nhl = 2;
    }
  else if (nl < 65536)
    {
      v3sig[0] = 0x89;
      v3sig[1] = nl >> 8;
      v3sig[2] = nl;
      nhl = 3;
    }
  else
    {
      fprintf(stderr, "v4tov3: new length too big\n");
      exit(1);
    }
  if (nhl + nl >= v3siglen + left)
    {
      fprintf(stderr, "v4tov3: no room left\n");
      exit(1);
    }
  memmove(v3sig + nhl, v4sigtrail, V4SIG_HASHED);
  memmove(v3sig + nhl + V4SIG_HASHED, v4sig_skel + V4SIG_HASHED, sizeof(v4sig_skel) - V4SIG_HASHED);

  memmove(v3sig + nhl + 16, issuer, 8);	/* issuer */
  memmove(v3sig + nhl + sizeof(v4sig_skel), v3sig + left + v3siglen - l, l);
  if (tail)
    memmove(v3sig + nhl + nl, v3sig + left + v3siglen, tail);
  return nhl + nl;
}

static int
probe_pubalgo()
{
  char hashhex[1024];
  byte buf[8192], *bp;
  u32 signtime = time(NULL);
  int i, sock, ulen, outl;

  sock = opensocket();
  ulen = strlen(user);
  bp = (byte *)hashhex;
  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
    sprintf((char *)bp, "01");
  sprintf((char *)bp, "@00%08x", (unsigned int)signtime);

  if (!privkey)
    {
      /* old style sign */
      if (ulen + strlen(hashhex) + 4 + 1 + (hashalgo == HASH_SHA1 ? 0 : strlen(hashname[hashalgo]) + 1) > sizeof(buf))
	{
	  close(sock);
	  return -1;
	}
      buf[0] = ulen >> 8;
      buf[1] = ulen;
      buf[2] = 0;
      buf[3] = 0;
      memmove(buf + 4, user, ulen);
      bp = buf + 4 + ulen;
      if (hashalgo != HASH_SHA1)
	{
	  strcpy((char *)bp, hashname[hashalgo]);
	  bp += strlen((const char *)bp);
	  *bp++ = ':';
	}
      strcpy((char *)bp, hashhex);
      bp += strlen((char *)bp);
      buf[3] = bp - (buf + 4 + ulen);
      outl = doreq_old(sock, buf, (int)(bp - buf), sizeof(buf));
    }
  else
    {
      const char *args[5];

      readprivkey();
      args[0] = "privsign";
      args[1] = algouser;
      args[2] = privkey;
      args[3] = hashhex;
      outl = doreq(sock, 4, args, buf, sizeof(buf), 1);
      if (outl >= 0)
	{
	  outl = buf[2] << 8 | buf[3];
	  memmove(buf, buf + 4, outl);
	}
    }
  return outl > 0 ? sigtopubalgo(buf, outl) : -1;
}

static int
sign(char *filename, int isfilter, int mode)
{
  u32 signtime;
  byte buf[8192], *bp;
  byte *cbuf;
  int cbufl;
  int l, fd;
  int i;
  byte hash[5], *p, *ph = 0;
  HASH_CONTEXT ctx;
  MD5_CTX md5ctx;
  HASH_CONTEXT hctx;
  int force = 1;
  int outl, outlh;
  int sock;
  int ulen;
  byte rpmlead[96];
  byte rpmsighead[16], *rsp;
  byte *rpmsig = 0;
  int rpmsigcnt = 0, rpmsigdlen = 0;
  int rpmsigsize = 0, tag;
  u32 lensig, lenhdr;
  byte rpmleadsum[16];
  byte rpmmd5sum[16];
  byte rpmmd5sum2[16];
  byte *hdrin_md5 = 0;
  u32 hdrin_size = 0;
  u32 rpmdataoff = 0;
  char *outfilename = 0;
  FILE *fout = 0;
  int foutfd = -1;
  int getbuildtime = 0;
  int buildtimeoff = 0;
  byte btbuf[4];
  int gotsha1 = 0;

  /* checksums over the complete signed rpm */
  MD5_CTX chksum_ctx_md5;
  SHA1_CONTEXT chksum_ctx_sha1;
  SHA256_CONTEXT chksum_ctx_sha256;
  byte chksum_md5[16];
  byte chksum_sha1[20];
  byte chksum_sha256[32];

  unsigned char *v4sigtrail = 0;
  int v4sigtraillen = 0;

  if (mode == MODE_UNSET)
    {
      force = 0;
      if (isfilter)
        {
	  fprintf(stderr, "please specify a mode for filter usage (see sign --help).\n");
	  exit(1);
        }
      l = strlen(filename);
      if (l > 4 && (!strcmp(filename + l - 4, ".rpm") || !strcmp(filename + l - 4, ".spm")))
	mode = MODE_RPMSIGN;
      else if (l > 9 && (!strcmp(filename + l - 9, ".AppImage"))) {
        mode = MODE_APPIMAGESIGN;
      } else
        mode = MODE_CLEARSIGN;
    }
  if (mode == MODE_APPIMAGESIGN && isfilter)
    {
      fprintf(stderr, "appimage sign cannot work as filter.\n");
      exit(1);
    }
  if (isfilter)
    fd = 0;
  else if ((fd = open(filename, O_RDONLY)) == -1)
    {
      perror(filename);
      exit(1);
    }
  else if (mode != MODE_APPIMAGESIGN)
    {
      outfilename = malloc(strlen(filename) + 16);
      if (!outfilename)
	{
	  fprintf(stderr, "out of memory for filename\n");
	  exit(1);
	}
      if (mode == MODE_DETACHEDSIGN)
	sprintf(outfilename, "%s.asc", filename);
      else if (mode == MODE_RAWDETACHEDSIGN || mode == MODE_RAWOPENSSLSIGN)
	sprintf(outfilename, "%s.sig", filename);
      else
	sprintf(outfilename, "%s.sIgN%d", filename, getpid());
    }
  if (!timearg || mode == MODE_KEYID || mode == MODE_PUBKEY)
    signtime = time(NULL);
  else if (*timearg >= '0' && *timearg <= '9')
    signtime = strtoul(timearg, NULL, 0);
  else if (mode == MODE_RPMSIGN && !strcmp(timearg, "buildtime"))
    {
      getbuildtime = 1;
      signtime = 0;		/* rpmsign && buildtime */
    }
  else
    {
      struct stat stb;
      if (fstat(fd, &stb))
	{
	  perror("fstat");
	  exit(1);
	}
      if (S_ISFIFO(stb.st_mode))
	{
	  fprintf(stderr, "cannot use mtime on pipes\n");
	  exit(1);
	}
      signtime = stb.st_mtime;
    }

  if (mode == MODE_RPMSIGN)
    {
      if (read(fd, rpmlead, 96) != 96 || rpmlead[0] != 0xed || rpmlead[1] != 0xab || rpmlead[2] != 0xee || rpmlead[3] != 0xdb)
	{
	  fprintf(stderr, "%s: not a rpm\n", filename);
	  exit(1);
	}
      if (rpmlead[4] != 0x03 || rpmlead[0x4e] != 0 || rpmlead[0x4f] != 5)
	{
	  fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", filename);
	  exit(1);
	}
      if (read(fd, rpmsighead, 16) != 16 || rpmsighead[0] != 0x8e || rpmsighead[1] != 0xad || rpmsighead[2] != 0xe8 || rpmsighead[3] != 0x01)
	{
	  fprintf(stderr, "%s: bad signature header\n", filename);
	  exit(1);
	}
      rpmsigcnt = rpmsighead[8] << 24 | rpmsighead[9] << 16 | rpmsighead[10] << 8 | rpmsighead[11];
      rpmsigdlen = rpmsighead[12] << 24 | rpmsighead[13] << 16 | rpmsighead[14] << 8 | rpmsighead[15];
      rpmsigsize = rpmsigcnt * 16 + ((rpmsigdlen + 7) & ~7);
      rpmsig = malloc(rpmsigsize + 2 * (1024 + 16 + 4));
      if (!rpmsig)
	{
	  fprintf(stderr, "%s: no memory for signature area\n", filename);
	  exit(1);
	}
      if (xread(fd, rpmsig, rpmsigsize) != rpmsigsize)
	{
	  fprintf(stderr, "%s: read error in signature area\n", filename);
	  exit(1);
	}
      rpmdataoff = 96 + 16 + rpmsigsize;
      rsp = rpmsig;
      for (i = 0; i < rpmsigcnt; i++)
	{
	  tag = rsp[0] << 24 | rsp[1] << 16 | rsp[2] << 8 | rsp[3];
	  if (tag == pubtag[PUB_DSA] || tag == pubtag[PUB_RSA] || tag == pubtagh[PUB_DSA] || tag == pubtagh[PUB_RSA])
	    {
	      fprintf(isfilter ? stderr : stdout, "%s: already signed\n", filename);
	      close(fd);
	      free(rpmsig);
	      if (outfilename)
		free(outfilename);
	      if (isfilter)
		exit(1);
	      return 1;
	    }
	  if (tag == RPMSIGTAG_SHA1)
	    gotsha1 = 1;
	  if (tag == RPMSIGTAG_MD5)
	    {
	      if (rsp[4] || rsp[5] || rsp[6] || rsp[7] != 7 || rsp[12] || rsp[13] || rsp[14] || rsp[15] != 16)
		{
		  fprintf(stderr, "%s: bad MD5 tag\n", filename);
		  exit(1);
		}
	      hdrin_md5 = rpmsig + rpmsigcnt * 16 + (rsp[8] << 24 | rsp[9] << 16 | rsp[10] << 8 | rsp[11]);
	    }
	  if (tag == RPMSIGTAG_SIZE)
	    {
	      if (rsp[4] || rsp[5] || rsp[6] || rsp[7] != 4 || rsp[12] || rsp[13] || rsp[14] || rsp[15] != 1)
		{
		  fprintf(stderr, "%s: bad SIZE tag\n", filename);
		  exit(1);
		}
	      p = rpmsig + rpmsigcnt * 16 + (rsp[8] << 24 | rsp[9] << 16 | rsp[10] << 8 | rsp[11]);
	      hdrin_size = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
	    }
	  rsp += 16;
	}
    }


  hash_init(&ctx);
  if (mode == MODE_CLEARSIGN)
    {
      int have = 0;
      int i, j;
      int nl = 0;
      int first = 1;

      if ((cbuf = malloc(8192)) == NULL)
	{
	  fprintf(stderr, "no mem for clearsign buffer\n");
	  exit(1);
	}
      cbufl = 8192;
      l = read(fd, cbuf, cbufl);
      if (l < 0)
	{
	  perror("read");
	  exit(1);
	}
      if (l >= 34 && !strncmp((char *)cbuf, "-----BEGIN PGP SIGNED MESSAGE-----", 34))
	{
	  fprintf(isfilter ? stderr : stdout, "%s: already signed\n", filename);
	  close(fd);
	  if (outfilename)
	    free(outfilename);
	  if (isfilter)
	    exit(1);
	  return(1);
	}
      for (i = 0; i < l; i++)
	{
	  if (cbuf[i] >= 32 || cbuf[i] == '\t' || cbuf[i] == '\r' || cbuf[i] == '\n')
	    continue;
	  first++;
	}
      if (first > 4 && !force)
	{
	  fprintf(stderr, "%s: won't clearsign binaries\n", filename);
	  exit(1);
	}
      sock = opensocket();
      if (isfilter)
	fout = stdout;
      else if ((fout = fopen(outfilename, "w")) == 0)
	{
	  perror(outfilename);
	  exit(1);
	}
      foutfd = fileno(fout);
      fprintf(fout, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: %s\n\n", hashname[hashalgo]);
      while (first || (l = read(fd, cbuf + have, cbufl - have)) > 0 || (l == 0 && have))
	{
	  first = 0;
	  if (nl)
	    hash_write(&ctx, (const unsigned char *)"\r\n",  2);
          nl = 0;
	  l += have;
	  for (i = 0; i < l; i++)
	    if (cbuf[i] == '\n')
	      break;
	  if (i == l && i == cbufl && l != have)
	    {
	      cbufl *= 2;
	      cbuf = realloc(cbuf, cbufl);
	      if (!cbuf)
		{
		  fprintf(stderr, "no mem for clearsign buffer\n");
		  exit(1);
		}
	      have = l;
	      continue;
	    }
          if ((l > 0 && cbuf[0] == '-') || (l > 4 && !strncmp((char *)cbuf, "From ", 5)))
	    fprintf(fout, "- ");
	  if (i == l)
	    {
	      /* EOF reached, line is unterminated */
	      cbuf[l] = '\n';
	      l++;
	    }
          if (i > 20000)
	    {
	      fprintf(stderr, "line too long for clearsign\n");
	      exit(1);
	    }
	  fwrite(cbuf, 1, i + 1, fout);
	  for (j = i - 1; j >= 0; j--)
	    if (cbuf[j] != '\r' && cbuf[j] != ' ' && cbuf[j] != '\t')
	      break;
	  if (j >= 0)
	    hash_write(&ctx, cbuf, j + 1);
	  nl = 1;
	  i++;
	  if (i < l)
	    memmove(cbuf, cbuf + i, l - i);
	  have = l - i;
	}
      if (l < 0)
	{
	  perror("read");
          if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      free(cbuf);
      cbuf = 0;
      cbufl = 0;
    }
  else if (mode == MODE_KEYID || mode == MODE_PUBKEY)
    {
      /* sign empty string */
      sock = opensocket();
    }
  else if (mode == MODE_APPIMAGESIGN)
    {
      unsigned char appimagedigest[64]; /*  sha256 sum */
      char *digestfilename;
      FILE *fp;

      sock = opensocket();
      digestfilename = malloc(strlen(filename) + 8);
      sprintf(digestfilename, "%s.digest", filename);
      if ((fp = fopen(digestfilename, "r")) == 0 || 64 != fread(appimagedigest, 1, 64, fp))
        {
          perror(digestfilename);
          exit(1);
        }
      fclose(fp);
      free(digestfilename);
      hash_write(&ctx, appimagedigest, 64);
    }
  else
    {
      sock = opensocket();
      if (mode == MODE_RPMSIGN)
	{
	  md5_init(&md5ctx);
	  hash_init(&hctx);
	}
      lensig = 0;
      lenhdr = 0;
      while ((l = read(fd, buf, sizeof(buf))) > 0)
	{
	  if (!lensig && mode == MODE_RPMSIGN)
	    {
	      if (l < 16)
		{
		  fprintf(stderr, "cannot calculate header size: short read\n");
		  exit(1);
		}
	      lenhdr = 16;
	      lenhdr += 16 * (buf[8] << 24 |  buf[9] << 16 | buf[10] << 8 | buf[11]);
	      lenhdr += buf[12] << 24 |  buf[13] << 16 | buf[14] << 8 | buf[15];
	    }
	  if (getbuildtime && !lensig)
	    {
	      int n;
	      n = buf[8] << 24 |  buf[9] << 16 | buf[10] << 8 | buf[11];
	      if ((l - 16) / 16 < n)
		n = (l - 16) / 16;
	      for (i = 0; i < n; i++)
		if (!memcmp(buf + 16 + 16 * i, "\0\0\003\356\0\0\0\4", 8))
		  break;
	      if (i == n)
		{
		  fprintf(stderr, "cannot calculate buildtime: tag not found\n");
		  exit(1);
		}
	      buildtimeoff = 16 + (buf[8] << 24 |  buf[9] << 16 | buf[10] << 8 | buf[11]) * 16;
	      i = 16 + 16 * i + 8;
	      buildtimeoff += buf[i] << 24 |  buf[i + 1] << 16 | buf[i + 2] << 8 | buf[i + 3];
	    }
	  if (getbuildtime && lensig < buildtimeoff + 4 && lensig + l > buildtimeoff)
	    {
	      for (i = 0; i < l; i++)
		if (lensig + i >= buildtimeoff && lensig + i < buildtimeoff + 4)
		  btbuf[lensig + i - buildtimeoff] = buf[i];
	    }
	  hash_write(&ctx, buf,  l);
	  if (mode == MODE_RPMSIGN)
	    {
	      md5_write(&md5ctx, buf, l);
	      if (lenhdr)
		{
		  if (l >= lenhdr)
		    {
		      hash_write(&hctx, buf,  lenhdr);
		      lenhdr = 0;
		    }
		  else
		    {
		      hash_write(&hctx, buf,  l);
		      lenhdr -= l;
		    }
		}
	    }
	  lensig += l;
	}
      if (mode == MODE_RPMSIGN)
	{
	  md5_final(rpmmd5sum, &md5ctx);
	  if (lenhdr)
	    {
	      fprintf(stderr, "%s: bad header size (%u)\n", filename, lenhdr);
	      exit(1);
	    }
	}
      if (hdrin_size && lensig != hdrin_size)
	{
	  fprintf(stderr, "%s: SIZE checksum error %d %d\n", filename, hdrin_size, lensig);
	  exit(1);
	}
      if (hdrin_md5 && memcmp(hdrin_md5, rpmmd5sum, 16))
	{
	  fprintf(stderr, "%s: MD5 checksum error\n", filename);
	  exit(1);
	}
      if (getbuildtime && lensig < buildtimeoff + 4)
	{
	  fprintf(stderr, "cannot calculate buildtime: bad data pointer\n");
	  exit(1);
	}
      if (getbuildtime)
	signtime = btbuf[0] << 24 | btbuf[1] << 16 | btbuf[2] << 8 | btbuf[3];
    }

  if (verbose && mode != MODE_KEYID && mode != MODE_PUBKEY)
    {
      if (*user)
        fprintf(isfilter ? stderr : stdout, "%s %s user %s\n", modes[mode],  filename, user);
      else
        fprintf(isfilter ? stderr : stdout, "%s %s\n", modes[mode],  filename);
    }
  if (mode != MODE_RAWOPENSSLSIGN && mode != MODE_KEYID && mode != MODE_PUBKEY && dov4sig)
    v4sigtrail = genv4sigtrail(mode, pubalgoprobe >= 0 ? pubalgoprobe : PUB_RSA, hashalgo, signtime, &v4sigtraillen);
  if (mode == MODE_RAWOPENSSLSIGN)
    {
      hash[0] = pkcs1pss ? 0xbc : 0x00;
      hash[1] = hash[2] = hash[3] = hash[4] = 0;
    }
  else
    {
      hash[0] = mode == MODE_CLEARSIGN ? 0x01 : 0x00; /* class */
      hash[1] = signtime >> 24;
      hash[2] = signtime >> 16;
      hash[3] = signtime >> 8;
      hash[4] = signtime;
      if (v4sigtrail)
        hash_write(&ctx, v4sigtrail, v4sigtraillen);
      else
        hash_write(&ctx, hash, 5);
    }
  hash_final(&ctx);
  p = hash_read(&ctx);
  ph = 0;
  outlh = 0;
  if (mode == MODE_RPMSIGN)
    {
      if (v4sigtrail)
        hash_write(&hctx, v4sigtrail, v4sigtraillen);
      else
        hash_write(&hctx, hash, 5);
      hash_final(&hctx);
      /* header only seems to work only if there's a header only hash */
      if (!noheaderonly && gotsha1)
        ph = hash_read(&hctx);
    }

  ulen = strlen(user);
  if (!privkey && !ph)
    {
      /* old style sign */
      if (ulen + hashlen[hashalgo] * 2 + 1 + 5 * 2 + 4 + 1 + (hashalgo == HASH_SHA1 ? 0 : strlen(hashname[hashalgo]) + 1) > sizeof(buf))
	{
	  fprintf(stderr, "packet too big\n");
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      buf[0] = ulen >> 8;
      buf[1] = ulen;
      buf[2] = 0;
      buf[3] = 0;
      memmove(buf + 4, user, ulen);
      bp = buf + 4 + ulen;
      if (hashalgo != HASH_SHA1)
	{
	  strcpy((char *)bp, hashname[hashalgo]);
	  bp += strlen((const char *)bp);
	  *bp++ = ':';
	}
      if (mode == MODE_PUBKEY)
	{
	  strcpy((char *)bp, "PUBKEY");
	  bp += 6;
	}
      else
	{
	  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	    sprintf((char *)bp, "%02x", p[i]);
	  *bp++ = '@';
	  for (i = 0; i < 5; i++, bp += 2)
	    sprintf((char *)bp, "%02x", hash[i]);
	}
      buf[3] = bp - (buf + 4 + ulen);
      outl = doreq_old(sock, buf, (int)(bp - buf), sizeof(buf));
      if (outl >= 0)
        memmove(buf + 6, buf, outl);	/* make 1st arg start at offset 6, we know there is room */
    }
  else
    {
      /* new style sign with doreq */
      const char *args[5];
      char *bp;
      char hashhex[1024];
      char hashhexh[1024];
      int argc;

      if (mode == MODE_PUBKEY)
	{
	  fprintf(stderr, "pubkey mode does not work with a private key\n");
	  exit(1);
	}
      if (privkey)
        readprivkey();
      bp = hashhex;
      for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	sprintf(bp, "%02x", p[i]);
      *bp++ = '@';
      for (i = 0; i < 5; i++, bp += 2)
	sprintf(bp, "%02x", hash[i]);
      *bp = 0;
      if (ph)
	{
	  bp = hashhexh;
	  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	    sprintf(bp, "%02x", ph[i]);
	  *bp++ = '@';
	  for (i = 0; i < 5; i++, bp += 2)
	    sprintf(bp, "%02x", hash[i]);
	  *bp = 0;
	}
      args[0] = privkey ? "privsign" : "sign";
      args[1] = algouser;
      argc = 2;
      if (privkey)
        args[argc++] = privkey;
      args[argc++] = hashhex;
      if (ph)
        args[argc++] = hashhexh;
      outl = doreq(sock, argc, args, buf, sizeof(buf), ph ? 2 : 1);
      if (outl >= 0)
	{
	  outl = buf[2] << 8 | buf[3];
	  outlh = ph ? (buf[4] << 8 | buf[5]) : 0;
	  if (outl == 0 || (ph && outlh == 0))
	    {
	      if (mode == MODE_CLEARSIGN && !isfilter)
		unlink(outfilename);
	      fprintf(stderr, "server returned empty signature\n");
	      exit(1);
	    }
	  if (!ph)
	    memmove(buf + 6, buf + 4, outl);	/* make 1st arg always start at offset 6, we know there is room */
	}
    }
  if (outl < 0)
    {
      if (mode == MODE_CLEARSIGN && !isfilter)
	unlink(outfilename);
      exit(-outl);
    }
  if (mode == MODE_KEYID)
    {
      int o;
      if (outl < 2)
	{
          fprintf(stderr, "answer package too short\n");
	  exit(1);
	}
      if (buf[6] == 0x88)
	o = 8;
      else if (buf[6] == 0x89)
	o = 9;
      else if (buf[6] == 0x8a)
	o = 11;
      else
	{
          fprintf(stderr, "bad answer package: %02x\n", buf[6]);
	  exit(1);
	}
      if (buf[o] == 3)
	{
	  printf("%02X%02X%02X%02X\n", buf[o + 11], buf[o + 12], buf[o + 13], buf[o + 14]);
	  exit(0);
	}
      else if (buf[o] == 4)
	{
	  /* assumes sign id is first in unhashed data */
	  o += (buf[o + 4] << 8) + buf[o + 5];	/* skip over hashed data */
	  if (buf[o + 9] != 16)
	    {
	      fprintf(stderr, "issuer not first in unhashed data\n");
	      exit(1);
	    }
	  printf("%02X%02X%02X%02X\n", buf[o + 14], buf[o + 15], buf[o + 16], buf[o + 17]);
	  exit(0);
	}
      else
	{
          fprintf(stderr, "unknown signature version: %d\n", buf[o]);
	  exit(1);
	}
    }

  /* transcode v3sigs to v4sigs if requested */
  if (v4sigtrail)
    {
      outl = v3tov4(v4sigtrail, buf + 6, outl, outlh, sizeof(buf) - 6 - outl - outlh);
      if (ph)
        outlh = v3tov4(v4sigtrail, buf + 6 + outl, outlh, 0, sizeof(buf) - 6 - outl - outlh);
      free(v4sigtrail);
    }

  if (isfilter)
    {
      fout = stdout;
      foutfd = 1;
    }
  else if (mode != MODE_CLEARSIGN && mode != MODE_APPIMAGESIGN)
    {
      if ((fout = fopen(outfilename, "w")) == 0)
	{
	  perror(outfilename);
	  exit(1);
	}
      foutfd = fileno(fout);
    }

  if (mode == MODE_CLEARSIGN || mode == MODE_DETACHEDSIGN)
    {
      write_armored_signature(fout, buf + 6, outl);
    }
  else if (mode == MODE_RAWDETACHEDSIGN)
    {
      if (fwrite(buf + 6, outl, 1, fout) != 1)
	{
	  perror("fwrite");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
    }
  else if (mode == MODE_RAWOPENSSLSIGN)
    {
      int off, pubalgo = sigtopubalgo(buf + 6, outl);
      int bytes;
      if (pubalgo != PUB_RSA)
	{
          fprintf(stderr, "Need RSA key for openssl sign\n");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      off = findsigoff(buf + 6, outl);
      if (off <= 0)
	{
          fprintf(stderr, "Could not determine offset\n");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (off + 2 > outl)
	{
          fprintf(stderr, "truncated sig\n");
	  exit(1);
	}
      bytes = ((buf[6 + off] << 8) + buf[7 + off] + 7) >> 3;
      if (off + 2 + bytes > outl)
	{
          fprintf(stderr, "truncated sig\n");
	  exit(1);
	}
      /* zero pad to multiple of 16 */
      if ((bytes & 15) != 0 && fwrite("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16 - (bytes & 15), 1, fout) != 1)
	{
	  perror("fwrite");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (fwrite(buf + 6 + off + 2, bytes, 1, fout) != 1)
	{
	  perror("fwrite");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
    }
  else if (mode == MODE_RPMSIGN)
    {
      if (rpminsertsig(rpmsig, &rpmsigsize, &rpmsigcnt, &rpmsigdlen, pubtag, buf + 6, outl))
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (outlh)
	{
	  if (rpminsertsig(rpmsig, &rpmsigsize, &rpmsigcnt, &rpmsigdlen, pubtagh, buf + 6 + outl, outlh))
	    {
	      if (!isfilter)
		unlink(outfilename);
	      exit(1);
	    }
	}
      rpmsighead[8]  = rpmsigcnt >> 24;
      rpmsighead[9]  = rpmsigcnt >> 16;
      rpmsighead[10] = rpmsigcnt >> 8 ;
      rpmsighead[11] = rpmsigcnt;

      rpmsighead[12] = rpmsigdlen >> 24;
      rpmsighead[13] = rpmsigdlen >> 16;
      rpmsighead[14] = rpmsigdlen >> 8 ;
      rpmsighead[15] = rpmsigdlen;

      if (lseek(fd, rpmdataoff, SEEK_SET) == (off_t)-1)
	{
	  perror("lseek");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}

      xwrite(foutfd, rpmlead, 96);
      xwrite(foutfd, rpmsighead, 16);
      xwrite(foutfd, rpmsig, rpmsigsize);

      if (chksumfilefd >= 0)
	{
	  md5_init(&md5ctx);
	  md5_write(&md5ctx, rpmlead, 96);
	  md5_write(&md5ctx, rpmsighead, 16);
	  md5_write(&md5ctx, rpmsig, rpmsigsize);
	  md5_final(rpmleadsum, &md5ctx);

	  md5_init(&chksum_ctx_md5);
	  md5_write(&chksum_ctx_md5, rpmlead, 96);
	  md5_write(&chksum_ctx_md5, rpmsighead, 16);
	  md5_write(&chksum_ctx_md5, rpmsig, rpmsigsize);

	  sha1_init(&chksum_ctx_sha1);
	  sha1_write(&chksum_ctx_sha1, rpmlead, 96);
	  sha1_write(&chksum_ctx_sha1, rpmsighead, 16);
	  sha1_write(&chksum_ctx_sha1, rpmsig, rpmsigsize);

	  sha256_init(&chksum_ctx_sha256);
	  sha256_write(&chksum_ctx_sha256, rpmlead, 96);
	  sha256_write(&chksum_ctx_sha256, rpmsighead, 16);
	  sha256_write(&chksum_ctx_sha256, rpmsig, rpmsigsize);
	}
      md5_init(&md5ctx);
      lensig = 0;
      while ((l = read(fd, buf, sizeof(buf))) > 0)
	{
	  md5_write(&md5ctx, buf, l);
	  xwrite(foutfd, buf, l);
	  if (chksumfilefd >= 0)
	    {
	      md5_write(&chksum_ctx_md5, buf, l);
	      sha1_write(&chksum_ctx_sha1, buf, l);
	      sha256_write(&chksum_ctx_sha256, buf, l);
	    }
	  lensig += l;
	}
      md5_final(rpmmd5sum2, &md5ctx);
      if (chksumfilefd >= 0)
	{
	  md5_final(chksum_md5, &chksum_ctx_md5);
	  sha1_final(&chksum_ctx_sha1);
	  memcpy(chksum_sha1, sha1_read(&chksum_ctx_sha1), 20);
	  sha256_final(&chksum_ctx_sha256);
	  memcpy(chksum_sha256, sha256_read(&chksum_ctx_sha256), 32);
	}
      if (memcmp(rpmmd5sum2, rpmmd5sum, 16))
	{
	  fprintf(stderr, "rpm has changed, bailing out!\n");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      free(rpmsig);
    }
  else if (mode == MODE_APPIMAGESIGN)
    write_appimage_signature(filename, buf + 6, outl);
  else
    fwrite(buf + 6, 1, outl, fout);

  if (!isfilter)
    {
      close(fd);
      if (fout && fclose(fout))
	{
	  perror("fclose");
	  unlink(outfilename);
	  exit(1);
	}
      if (mode != MODE_DETACHEDSIGN && mode != MODE_RAWDETACHEDSIGN
	  && mode != MODE_RAWOPENSSLSIGN && mode != MODE_APPIMAGESIGN
	  && rename(outfilename, filename))
	{
	  perror("rename");
	  unlink(outfilename);
	  exit(1);
	}
    }
  if (outfilename)
    free(outfilename);
  if (mode == MODE_RPMSIGN && chksumfilefd >= 0)
    {
      char buf[16*2 + 5+16*2 + 6+20*2 + 8+32*2 + 1], *bp;
      bp = buf;
      for (i = 0; i < 16; i++)
	{
	  sprintf(bp, "%02x", rpmleadsum[i]);
	  bp += 2;
	}
      strcpy(bp, " md5:");
      bp += 5;
      for (i = 0; i < 16; i++)
	{
	  sprintf(bp, "%02x", chksum_md5[i]);
	  bp += 2;
	}
      strcpy(bp, " sha1:");
      bp += 6;
      for (i = 0; i < 20; i++)
	{
	  sprintf(bp, "%02x", chksum_sha1[i]);
	  bp += 2;
	}
      strcpy(bp, " sha256:");
      bp += 8;
      for (i = 0; i < 32; i++)
	{
	  sprintf(bp, "%02x", chksum_sha256[i]);
	  bp += 2;
	}
      *bp++ = '\n';
      if (write(chksumfilefd, buf, bp - buf) != bp - buf)
	{
	  perror("chksum write");
	  exit(1);
	}
    }
  return 0;
}

static void
keygen(const char *type, const char *expire, const char *name,
       const char *email)
{
  const char *args[6];
  byte buf[8192];
  int l, publ, privl;
  int sock = opensocket();

  args[0] = "keygen";
  args[1] = algouser;
  args[2] = type;
  args[3] = expire;
  args[4] = name;
  args[5] = email;
  l = doreq(sock, 6, args, buf, sizeof(buf), 2);
  close(sock);
  if (l < 0)
    exit(-l);
  publ = buf[2] << 8 | buf[3];
  privl = buf[4] << 8 | buf[5];
  if (privkey && strcmp(privkey, "-"))
    {
      int fout;
      char *outfilename = malloc(strlen(privkey) + 16);

      sprintf(outfilename, "%s.sIgN%d", privkey, getpid());
      if ((fout = open(outfilename, O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1)
	{
	  perror(outfilename);
	  exit(1);
	}
      if (write(fout, buf + 6 + publ, privl) != privl)
	{
	  perror("privkey write error");
	  exit(1);
	}
      if (write(fout, "\n", 1) != 1)
	{
	  perror("privkey write error");
	  exit(1);
	}
      if (close(fout))
	{
	  perror("privkey write error");
	  exit(1);
	}
      if (rename(outfilename, privkey))
	{
	  perror(privkey);
	  exit(1);
	}
    }
  else
    {
      if (fwrite(buf + 6 + publ, privl, 1, stdout) != 1)
	{
	  fprintf(stderr, "privkey write error\n");
	  exit(1);
	}
      printf("\n");
    }
  if (fwrite(buf + 6, publ, 1, stdout) != 1)
    {
      fprintf(stderr, "pubkey write error\n");
      exit(1);
    }
  if (fflush(stdout))
    {
      fprintf(stderr, "pubkey write error\n");
      exit(1);
    }
  exit(0);
}

static char *
r64dec1(char *p, unsigned int *vp, int *eofp)
{
  int i, x;
  unsigned int v = 0;

  for (i = 0; i < 4; )
    {
      x = *p++;
      if (!x)
        return 0;
      if (x >= 'A' && x <= 'Z')
        x -= 'A';
      else if (x >= 'a' && x <= 'z')
        x -= 'a' - 26;
      else if (x >= '0' && x <= '9')
        x -= '0' - 52;
      else if (x == '+')
        x = 62;
      else if (x == '/')
        x = 63;
      else if (x == '=')
        {
          x = 0;
          if (i == 0)
            {
              *eofp = 3;
              *vp = 0;
              return p - 1;
            }
          *eofp += 1;
        }
      else
        continue;
      v = v << 6 | x;
      i++;
    }
  *vp = v;
  return p;
}

static unsigned char *
unarmor(char *pubkey, int *pktlp)
{
  char *p;
  int l, eof;
  unsigned char *buf, *bp;
  unsigned int v;

  *pktlp = 0;
  while (strncmp(pubkey, "-----BEGIN PGP PUBLIC KEY BLOCK-----", 36) != 0)
    {
      pubkey = strchr(pubkey, '\n');
      if (!pubkey)
        return 0;
      pubkey++;
    }
  pubkey = strchr(pubkey, '\n');
  if (!pubkey++)
    return 0;
  /* skip header lines */
  for (;;)
    {
      while (*pubkey == ' ' || *pubkey == '\t')
        pubkey++;
      if (*pubkey == '\n')
        break;
      pubkey = strchr(pubkey, '\n');
      if (!pubkey++)
        return 0;
    }
  pubkey++;
  p = strchr(pubkey, '=');
  if (!p)
    return 0;
  l = p - pubkey;
  bp = buf = malloc(l * 3 / 4 + 4 + 16);
  eof = 0;
  while (!eof)
    {
      pubkey = r64dec1(pubkey, &v, &eof);
      if (!pubkey)
        {
          free(buf);
          return 0;
        }
      *bp++ = v >> 16;
      *bp++ = v >> 8;
      *bp++ = v;
    }
  while (*pubkey == ' ' || *pubkey == '\t' || *pubkey == '\n' || *pubkey == '\r')
    pubkey++;
  bp -= eof;
  if (*pubkey != '=' || (pubkey = r64dec1(pubkey + 1, &v, &eof)) == 0)
    {
      free(buf);
      return 0;
    }
  if (v != crc24(buf, bp - buf))
    {
      free(buf);
      return 0;
    }
  while (*pubkey == ' ' || *pubkey == '\t' || *pubkey == '\n' || *pubkey == '\r')
    pubkey++;
  if (strncmp(pubkey, "-----END PGP PUBLIC KEY BLOCK-----", 34) != 0)
    {
      free(buf);
      return 0;
    }
  *pktlp = bp - buf;
  return buf;
}

static unsigned char *
nextpkg(int *tagp, int *pkgl, unsigned char **pp, int *ppl)
{
  int x, l;
  unsigned char *p = *pp;
  int pl = *ppl;
  int tag;

  *tagp = 0;
  if (!pl)
    return 0;
  x = *p++;
  pl--;
  if (!(x & 128) || pl <= 0)
    return 0;
  if ((x & 64) == 0)
    {
      /* old format */
      tag = (x & 0x3c) >> 2;
      x &= 3;
      if (x == 3)
	return 0;
      l = 1 << x;
      if (pl < l)
	return 0;
      x = 0;
      while (l--)
	{
	  x = x << 8 | *p++;
	  pl--;
	}
      l = x;
    }
  else
    {
      tag = (x & 0x3f);
      x = *p++;
      pl--;
      if (x < 192)
	l = x;
      else if (x >= 192 && x < 224)
	{
	  if (pl <= 0)
	    return 0;
	  l = ((x - 192) << 8) + *p++ + 192;
	  pl--;
	}
      else if (x == 255)
	{
	  if (pl <= 4)
	    return 0;
	  l = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
	  p += 4;
	  pl -= 4;
	}
      else
	return 0;
    }
  if (pl < l)
    return 0;
  *pp = p + l;
  *ppl = pl - l;
  *pkgl = l;
  *tagp = tag;
  return p;
}

static unsigned char *
finddate(unsigned char *q, int l, int type)
{
  int x;
  int ql = q[0] << 8 | q[1];
  q += 2;
  if (ql + 2 > l)
    return 0;
  while (ql)
    {
      int sl;
      x = *q++;
      ql--;
      if (x < 192)
	sl = x;
      else if (x == 255)
	{
	  if (ql < 4)
	    return 0;
	  sl = q[0] << 24 | q[1] << 16 | q[2] << 8 | q[3];
	  q += 4;
	  ql -= 4;
	}
      else
	{
	  if (ql < 1)
	    return 0;
	  sl = ((x - 192) << 8) + *q++ + 192;
	  ql--;
	}
      if (ql < sl)
	return 0;
      x = q[0] & 127;
      if (x == type)
	return q + 1;
      q += sl;
      ql -= sl;
    }
  return 0;
}

static unsigned char *
addpkg(unsigned char *to, unsigned char *p, int l, int tag, int newformat)
{
  /* we know that l < 8192 */
  if (!newformat)
    {
      if (l < 256)
	{
	  *to++ = 128 | tag << 2;
	  *to++ = l;
	}
      else
	{
	  *to++ = 128 | tag << 2 | 1;
	  *to++ = l >> 8;
	  *to++ = l;
	}
    }
  else
    {
      *to++ = 128 | 64 | tag;
      if (l < 192)
	*to++ = l;
      else
	{
	  *to++ = ((l - 192) >> 8) + 192;
	  *to++ = (l - 192);
	}
    }
  memmove(to, p, l);
  return to + l;
}



void
keyextend(char *expire, char *pubkey)
{
  FILE *fp;
  char buf[8192];
  unsigned char rbuf[8192];
  unsigned char *pubk, *p, *pp;
  int i, l, ll, pubkl, tag, pl;
  unsigned char b[6];
  unsigned char *newpubk, *selfsigpkg;
  unsigned char *issuer;

  unsigned char *pk;
  int pkl;
  time_t pkcreat;
  unsigned char *userid;
  int useridl;

  int hl;
  unsigned char *ex;
  time_t now;
  int expdays;

  SHA1_CONTEXT fingerprint;
  unsigned char *fingerprintp;

  HASH_CONTEXT dig;
  unsigned char *digp;

  const char *args[5];
  char *bp;
  char hashhex[1024];
  int argc;
  int sock = -1;
  unsigned char *rsig, *rsigp;
  int rsigl, rl;

  u32 crc;

  if (uid && !privkey)
    {
      fprintf(stderr, "need -P option for non-root operation\n");
      exit(1);
    }
  expdays = atoi(expire);
  if (expdays <= 0 || expdays >= 10000)
    {
      fprintf(stderr, "bad expire argument\n");
      exit(1);
    }
  if ((fp = fopen(pubkey, "r")) == 0)
    {
      perror(pubkey);
      exit(1);
    }
  l = 0;
  while (l < 8192 && (ll = fread(buf + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 8192)
    {
      fprintf(stderr, "pubkey too big\n");
      exit(1);
    }
  pubk = unarmor(buf, &pubkl);
  if (!pubk)
    {
      fprintf(stderr, "could not parse pubkey armor\n");
      exit(1);
    }
  p = pubk;
  l = pubkl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 6)
    {
      fprintf(stderr, "pubkey does not start with a pubkey paket\n");
      exit(1);
    }
  if (*pp != 4)
    {
      fprintf(stderr, "pubkey is not type 4\n");
      exit(1);
    }
  pkcreat = pp[1] << 24 | pp[2] << 16 | pp[3] << 8 | pp[4];
  pk = pp;
  pkl = pl;
  sha1_init(&fingerprint);
  b[0] = 0x99;
  b[1] = pkl >> 8;
  b[2] = pkl;
  sha1_write(&fingerprint, b, 3);
  sha1_write(&fingerprint, pk, pkl);
  sha1_final(&fingerprint);
  fingerprintp = sha1_read(&fingerprint);

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 13)
    {
      fprintf(stderr, "missing userid\n");
      exit(1);
    }
  userid = pp;
  useridl = pl;

  selfsigpkg = p;
  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 2)
    {
      fprintf(stderr, "missing self-sig\n");
      exit(1);
    }
  if (pp[0] != 4)
    {
      fprintf(stderr, "self-sig is not type 4\n");
      exit(1);
    }
  if (pp[1] != 0x13)
    {
      fprintf(stderr, "self-sig is not class 0x13\n");
      exit(1);
    }
  if (pp[3] == 9 || pp[3] == 10 || pp[3] == 11)
    pp[3] = 8;	/* change sha384/512/224 to sha256 for now */
  if (pp[3] == 2)
    hashalgo = HASH_SHA1;
  else if (pp[3] == 8)
    hashalgo = HASH_SHA256;
  else
    {
      fprintf(stderr, "self-sig hash type is unsupported (algo %d)\n", pp[3]);
      exit(1);
    }
  if (algouser && algouser != user)
    free(algouser);
  if (hashalgo == HASH_SHA1)
    algouser = user;
  else
    {
      algouser = malloc(strlen(user) + strlen(hashname[hashalgo]) + 2);
      sprintf(algouser, "%s:%s", hashname[hashalgo], user);
    }
  if (pl < 6)
    {
      fprintf(stderr, "self-sig is too short\n");
      exit(1);
    }
  ex = finddate(pp + 4, pl - 4, 2);
  if (!ex)
    {
      fprintf(stderr, "self-sig has no creation time\n");
      exit(1);
    }
  now = (u32)time((time_t)0);
  ex[0] = now >> 24;
  ex[1] = now >> 16;
  ex[2] = now >> 8;
  ex[3] = now;

  ex = finddate(pp + 4, pl - 4, 9);
  if (!ex)
    {
      fprintf(stderr, "self-sig does not expire\n");
      exit(1);
    }
  now = (now - pkcreat) + expdays * (24 * 3600);
  ex[0] = now >> 24;
  ex[1] = now >> 16;
  ex[2] = now >> 8;
  ex[3] = now;

  /* now create new digest */
  hash_init(&dig);
  b[0] = 0x99;
  b[1] = pkl >> 8;
  b[2] = pkl;
  hash_write(&dig, b, 3);
  hash_write(&dig, pk, pkl);
  b[0] = 0xb4;
  b[1] = useridl >> 24;
  b[2] = useridl >> 16;
  b[3] = useridl >> 8;
  b[4] = useridl;
  hash_write(&dig, b, 5);
  hash_write(&dig, userid, useridl);

  hl = 4 + 2 + ((pp[4] << 8) | pp[5]);
  issuer = finddate(pp + 4, pl - 4, 16);
  if (!issuer)
    issuer = finddate(pp + hl, pl - hl, 16);
  if (hl > pl)
    {
      fprintf(stderr, "self-sig has bad hashed-length\n");
      exit(1);
    }
  hash_write(&dig, pp, hl);
  b[0] = 4;
  b[1] = 0xff;
  b[2] = hl >> 24;
  b[3] = hl >> 16;
  b[4] = hl >> 8;
  b[5] = hl;
  hash_write(&dig, b, 6);
  hash_final(&dig);
  digp = hash_read(&dig);

  hl += 2 + (pp[hl] << 8 | pp[hl + 1]);
  if (hl > pl)
    {
      fprintf(stderr, "self-sig has bad length\n");
      exit(1);
    }

  now = (u32)time((time_t)0);
  b[0] = 0;
  b[1] = now >> 24;
  b[2] = now >> 16;
  b[3] = now >> 8;
  b[4] = now;

  if (privkey)
    readprivkey();
  bp = hashhex;
  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
    sprintf((char *)bp, "%02x", digp[i]);
  *bp++ = '@';
  for (i = 0; i < 5; i++, bp += 2)
    sprintf((char *)bp, "%02x", b[i]);
  *bp = 0;
  args[0] = privkey ? "privsign" : "sign";
  args[1] = algouser;
  argc = 2;
  if (privkey)
    args[argc++] = privkey;
  args[argc++] = hashhex;
  sock = opensocket();
  rl = doreq(sock, argc, args, rbuf, sizeof(rbuf), 1);
  close(sock);
  sock = -1;
  if (rl < 0)
    exit(-rl);
  if (rbuf[0] != 0 || rbuf[1] != 1)
    {
      fprintf(stderr, "bad return count\n");
      exit(1);
    }
  ll = rbuf[2] << 8 | rbuf[3];
  if (ll > rl - 2)
    {
      fprintf(stderr, "returned sig too small\n");
      exit(1);
    }
  rsigp = rbuf + 4;
  rsig = nextpkg(&tag, &rsigl, &rsigp, &ll);
  if (tag != 2)
    {
      fprintf(stderr, "returned data is no sig\n");
      exit(1);
    }
  if (*rsig != 3)
    {
      fprintf(stderr, "returned data is no V3 sig\n");
      exit(1);
    }
  if (issuer && memcmp(issuer, rsig + 7, 4))
    {
      fprintf(stderr, "issuer does not match, did you forget -P?\n");
      exit(1);
    }
  if (memcmp(fingerprintp + 12, rsig + 7, 8))
    {
      fprintf(stderr, "fingerprint does not match self sig\n");
      exit(1);
    }
  newpubk = malloc(pubkl + (rsigl - 17) - (pl - hl) + 6);
  memcpy(newpubk, pubk, selfsigpkg - pubk);
  memcpy(newpubk + (selfsigpkg - pubk) + 4, pp, pl);
  memcpy(newpubk + (selfsigpkg - pubk) + 4 + hl, rsig + 17, rsigl - 17);
  pp = addpkg(newpubk + (selfsigpkg - pubk), newpubk + (selfsigpkg - pubk) + 4, pl + (rsigl - 17) - (pl - hl), 2, selfsigpkg[0] & 64);
  if (l)
    {
      memcpy(pp, p, l);
      pp += l;
    }
  printf("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1.4.5 (GNU/Linux)\n\n");
  printr64(stdout, newpubk, pp - newpubk);
  crc = crc24((byte *)newpubk, pp - newpubk);
  b[0] = crc >> 16;
  b[1] = crc >> 8;
  b[2] = crc;
  putc('=', stdout);
  printr64(stdout, b, 3);
  printf("-----END PGP PUBLIC KEY BLOCK-----\n");
}

static void
certsizelimit(char *s, int l)
{
  if (strlen(s) <= l)
    return;
  s[l] = 0;
  s[l - 1] = s[l - 2] = s[l - 3] = '.';
}

void
createcert(char *pubkey)
{
  FILE *fp;
  char buf[8192];
  unsigned char rbuf[8192];
  unsigned char *pubk;
  int pubkl;
  unsigned char *p, *pp;
  int l, ll, tag, pl;
  time_t pkcreat, now, exp;
  unsigned char *ex;
  unsigned char *userid;
  int useridl;
  const char *args[6];
  int argc;
  int sock = -1;
  int rl;
  char *name, *nameend;
  char *email;
  char expire[20];

  if (!privkey)
    {
      fprintf(stderr, "need -P option for cert creation\n");
      exit(1);
    }
  if (privkey)
    readprivkey();
  if ((fp = fopen(pubkey, "r")) == 0)
    {
      perror(pubkey);
      exit(1);
    }
  l = 0;
  while (l < 8192 && (ll = fread(buf + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 8192)
    {
      fprintf(stderr, "pubkey too big\n");
      exit(1);
    }
  pubk = unarmor(buf, &pubkl);
  if (!pubk)
    {
      fprintf(stderr, "could not parse pubkey armor\n");
      exit(1);
    }
  p = pubk;
  l = pubkl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 6)
    {
      fprintf(stderr, "pubkey does not start with a pubkey paket\n");
      exit(1);
    }
  if (*pp != 4)
    {
      fprintf(stderr, "pubkey is not type 4\n");
      exit(1);
    }
  pkcreat = pp[1] << 24 | pp[2] << 16 | pp[3] << 8 | pp[4];
  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 13)
    {
      fprintf(stderr, "missing userid\n");
      exit(1);
    }
  userid = pp;
  useridl = pl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 2)
    {
      fprintf(stderr, "missing self-sig\n");
      exit(1);
    }
  if (pp[0] != 4)
    {
      fprintf(stderr, "self-sig is not type 4\n");
      exit(1);
    }
  if (pp[1] != 0x13)
    {
      fprintf(stderr, "self-sig is not class 0x13\n");
      exit(1);
    }
  if (pl < 6)
    {
      fprintf(stderr, "self-sig is too short\n");
      exit(1);
    }
  ex = finddate(pp + 4, pl - 4, 2);
  if (!ex)
    {
      fprintf(stderr, "self-sig has no creation time\n");
      exit(1);
    }
  now = (u32)time((time_t)0);
  ex = finddate(pp + 4, pl - 4, 9);
  if (!ex)
    {
      fprintf(stderr, "self-sig does not expire\n");
      exit(1);
    }
  exp = pkcreat + (ex[0] << 24 | ex[1] << 16 | ex[2] << 8 | ex[3]);
  if (exp < now)
    {
      fprintf(stderr, "pubkey is already expired\n");
      exit(1);
    }
  sprintf(expire, "%d", (int)(exp - now + 24 * 3600 - 1) / (24 * 3600));
  name = malloc(useridl + 1);
  if (!name)
    {
      fprintf(stderr, "out of mem\n");
      exit(1);
    }
  strncpy(name, (char *)userid, useridl);
  name[useridl] = 0;
  if (!useridl || name[useridl - 1] != '>')
    {
      fprintf(stderr, "userid does not end with email\n");
      exit(1);
    }
  name[useridl - 1] = 0;
  email = strrchr(name, '<');
  if (!email || email == name)
    {
      fprintf(stderr, "userid does not end with email\n");
      exit(1);
    }
  nameend = email;
  *email++ = 0;
  while (nameend > name && (nameend[-1] == ' ' || nameend[-1] == '\t'))
    *--nameend = 0;
  /* limit to fixed sizes, see rfc 3280 */
  certsizelimit(name, 64);
  certsizelimit(email, 128);
  args[0] = "certgen";
  args[1] = algouser;
  args[2] = privkey;
  args[3] = expire;
  args[4] = name;
  args[5] = email;
  argc = 6;

  sock = opensocket();
  rl = doreq(sock, argc, args, rbuf, sizeof(rbuf), 0);
  close(sock);
  if (rl < 0)
    exit(-rl);
  if (fwrite(rbuf, rl, 1, stdout) != 1)
    {
      fprintf(stderr, "cert write error\n");
      exit(1);
    }
  free(name);
}

void usage()
{
    fprintf(stderr, "usage:  sign [-v] [options]\n\n"
            "  sign [-v] -c <file> [-u user] [-h hash]: add clearsign signature\n"
            "  sign [-v] -d <file> [-u user] [-h hash]: create detached signature\n"
            "  sign [-v] -r <file> [-u user] [-h hash]: add signature block to rpm\n"
            "  sign [-v] -a <file> [-u user] [-h hash]: add signature block to appimage\n"
            "  sign [-v] -k [-u user] [-h hash]: print key id\n"
            "  sign [-v] -p [-u user] [-h hash]: print public key\n"
            "  sign [-v] -g <type> <expire> <name> <email>: generate keys\n"
            "  sign [-v] -x <expire> <pubkey>: extend pubkey\n"
            "  sign [-v] -C <pubkey>: create certificate\n"
            "  sign [-v] -t: test connection to signd server\n"
            //"  -D: RAWDETACHEDSIGN\n"
            //"  -O: RAWOPENSSLSIGN\n"
            //"  --noheaderonly\n"
            //"  -S <file>: verify checksum\n"
            //"  -T  time?\n"
            //"  -P  privkey\n" 
            "\n"
           );
}

int
main(int argc, char **argv)
{
  FILE *cfp;
  char buf[256], *bp;
  int c, l;
  int allowuser = 0;
  struct passwd *pwd = 0;
  int mode = MODE_UNSET;

  uid = getuid();
  if (uid)
    pwd = getpwuid(uid);
  user = strdup("");
  host = strdup("127.0.0.1");
  if ((cfp = fopen("/etc/sign.conf", "r")) == 0)
    {
      perror("/etc/sign.conf");
      exit(1);
    }
  while (fgets(buf, sizeof(buf), cfp))
    {
      l = strlen(buf);
      if (!l)
	continue;
      if (buf[l - 1] != '\n')
	{
	  while ((c = getc(cfp)) != EOF)
	    if (c == '\n')
	      break;
	  continue;
	}
      if (*buf == '#')
	continue;
      buf[--l] = ' ';
      while (l && (buf[l] == ' ' || buf[l] == '\t'))
	buf[l--] = 0;
      for (bp = buf; *bp && *bp != ':'; bp++)
	;
      if (!*bp)
	continue;
      *bp++ = 0;
      while (*bp == ' ' || *bp == '\t')
	bp++;
      if (!strcmp(buf, "user"))
	{
	  user = strdup(bp);
	  continue;
	}
      if (!strcmp(buf, "server"))
	{
	  host = strdup(bp);
	  continue;
	}
      if (!strcmp(buf, "port"))
	{
	  port = atoi(bp);
	  continue;
	}
      if (!strcmp(buf, "hash"))
	{
	  if (!strcasecmp(bp, "sha1"))
	    hashalgo = HASH_SHA1;
	  else if (!strcasecmp(bp, "sha256"))
	    hashalgo = HASH_SHA256;
	  else
	    {
	      fprintf(stderr, "sign: hash: unknown argument\n");
	      exit(1);
	    }
	}
      if (uid && !allowuser && !strcmp(buf, "allowuser"))
	{
	  if (pwd && !strcmp(pwd->pw_name, bp))
	    allowuser = 1;
	  else
	    {
	      long int li;
	      char *ep = 0;
	      li = strtol(bp, &ep, 10);
	      if (*ep == 0 && li == (long int)uid)
		allowuser = 1;
	    }
	}
    }
  fclose(cfp);
  if (uid)
    {
      if (!allowuser)
	{
	  fprintf(stderr, "sign: permission denied\n");
	  exit(1);
	}
      if (seteuid(uid))
	{
	  perror("seteuid");
	  exit(1);
	}
    }
  if (argc == 2 && !strcmp(argv[1], "-t"))
    {
      char buf[6];
      int r;
      int sock = opensocket();
      if (sock == -1)
	exit(1);
      if (write(sock, "\0\0\0\0", 4) != 4)
	{
	  perror("write");
	  exit(1);
	}
      r = read(sock, buf, 6);
      if (r == -1)
	{
	  perror("read");
	  exit(1);
	}
      close(sock);
      if (r != 6)
	exit(1);
      exit(buf[0] << 8 | buf[1]);
    }
  while (argc > 1)
    {
      if (!strcmp(argv[1], "--help"))
      {
          usage();
          exit(0);
      } else if (argc > 2 && !strcmp(argv[1], "-u"))
	{
	  user = argv[2];
	  argc -= 2;
	  argv += 2;
	}
      else if (argc > 2 && !strcmp(argv[1], "-h"))
	{
	  if (!strcasecmp(argv[2], "sha1"))
	    hashalgo = HASH_SHA1;
	  else if (!strcasecmp(argv[2], "sha256"))
	    hashalgo = HASH_SHA256;
	  else
	    {
	      fprintf(stderr, "sign: unknown hash algorithm '%s'\n", argv[2]);
	      exit(1);
	    }
	  argc -= 2;
	  argv += 2;
	}
      else if (argc > 1 && !strcmp(argv[1], "-c"))
	{
	  mode = MODE_CLEARSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-d"))
	{
	  mode = MODE_DETACHEDSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-D"))
	{
	  mode = MODE_RAWDETACHEDSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-O"))
	{
	  mode = MODE_RAWOPENSSLSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-r"))
	{
	  mode = MODE_RPMSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-a"))
	{
	  mode = MODE_APPIMAGESIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-v"))
	{
	  verbose++;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "--noheaderonly"))
        {
	  noheaderonly = 1;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-k"))
        {
	  mode = MODE_KEYID;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-p"))
        {
	  mode = MODE_PUBKEY;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-g"))
        {
	  mode = MODE_KEYGEN;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-x"))
        {
	  mode = MODE_KEYEXTEND;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-C"))
        {
	  mode = MODE_CREATECERT;
	  argc--;
	  argv++;
	}
      else if (argc > 2 && !strcmp(argv[1], "-S"))
	{
	  chksumfile = argv[2];
	  argc -= 2;
	  argv += 2;
	}
      else if (argc > 2 && !strcmp(argv[1], "-T"))
	{
	  timearg = argv[2];
	  argc -= 2;
	  argv += 2;
	  if (!*timearg || ((*timearg < '0' || *timearg > '9') && strcmp(timearg, "mtime") && strcmp(timearg, "buildtime")))
	    {
	      fprintf(stderr, "illegal time argument: %s\n", timearg);
	      exit(1);
	    }
	}
      else if (argc > 2 && !strcmp(argv[1], "-P"))
        {
	  privkey = argv[2];
	  argc -= 2;
	  argv += 2;
        }
      else if (argc > 1 && !strcmp(argv[1], "--pkcs1pss"))
        {
	  pkcs1pss = 1;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-4"))
        {
	  dov4sig = 1;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "--"))
        {
	  argc--;
	  argv++;
	  break;
        }
      else if (argc > 1 && argv[1][0] == '-')
	{
	  usage();
	  exit(1);
	}
      else
        break;
    }
  if (hashalgo == HASH_SHA1)
    algouser = user;
  else
    {
      algouser = malloc(strlen(user) + strlen(hashname[hashalgo]) + 2);
      sprintf(algouser, "%s:%s", hashname[hashalgo], user);
    }
  if ((mode == MODE_KEYID || mode == MODE_PUBKEY) && argc > 1)
    {
      fprintf(stderr, "usage: sign [-c|-d|-r|-a] [-u user] <file>\n");
      exit(1);
    }
  if (pkcs1pss && mode != MODE_RAWOPENSSLSIGN)
    {
      fprintf(stderr, "can only generate a pkcs1pss signature in openssl mode\n");
      exit(1);
    }
  if (mode == MODE_KEYGEN)
    {
      if (argc != 5)
	{
	  fprintf(stderr, "usage: sign -g <type> <expire> <name> <email>\n");
	  exit(1);
	}
      keygen(argv[1], argv[2], argv[3], argv[4]);
      exit(0);
    }
  if (mode == MODE_KEYEXTEND)
    {
      if (argc != 3)
	{
	  fprintf(stderr, "usage: sign -x <expire> <pubkey>\n");
	  exit(1);
	}
      keyextend(argv[1], argv[2]);
      exit(0);
    }
  if (mode == MODE_CREATECERT)
    {
      if (argc != 2)
	{
	  fprintf(stderr, "usage: sign -C <pubkey>\n");
	  exit(1);
	}
      createcert(argv[1]);
      exit(0);
    }
  if (privkey && access(privkey, R_OK))
    {
      perror(privkey);
      exit(1);
    }

  if (dov4sig && mode != MODE_KEYID && mode != MODE_PUBKEY && mode != MODE_RAWOPENSSLSIGN)
    pubalgoprobe = probe_pubalgo();

  if (chksumfile)
    {
      if (strcmp(chksumfile, "-"))
	chksumfilefd = open(chksumfile, O_WRONLY|O_CREAT|O_APPEND, 0666);
      else
	chksumfilefd = 1;
      if (chksumfilefd < 0)
	{
	  perror(chksumfile); 
	  exit(1);
	}
    }
  if (argc == 1)
    sign("<stdin>", 1, mode);
  else while (argc > 1)
    {
      sign(argv[1], 0, mode);
      argv++;
      argc--;
    }
  if (chksumfile && strcmp(chksumfile, "-") && chksumfilefd >= 0)
    {
      if (close(chksumfilefd))
	{
	  perror("chksum file close");
	  exit(1);
	}
    }
  exit(0);
}

