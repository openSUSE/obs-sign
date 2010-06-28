/*
 * Copyright (c) 2006, 2007, 2008 Michael Schroeder, Novell Inc.
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

char *host;
char *user;
char *algouser;
int port = MYPORT;

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
sha1_transform( SHA1_CONTEXT *hd, byte *data )
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
sha1_write( SHA1_CONTEXT *hd, byte *inbuf, size_t inlen)
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
sha256_transform( SHA256_CONTEXT *hd, byte *data )
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
sha256_write( SHA256_CONTEXT *hd, byte *inbuf, size_t inlen)
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
        t = (u32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
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
    if ((ctx->bits[0] = t + ((u32) len << 3)) < t)
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
    memset(ctx, 0, sizeof(ctx));        /* In case it's sensitive */
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


u32
crc24(byte *octets, int len)
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

void
printr64(FILE *f, byte *str, int len)
{
  int a, b, c, i;
  static byte bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  i = 0;
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

ssize_t xread(int fd, void *buf, size_t count)
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

ssize_t xwrite(int fd, void *buf, size_t count)
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

uid_t uid;

int opensocket()
{
  static int hostknown;
  static struct sockaddr_in svt;
  int sock;

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
	  memmove((char *)&svt.sin_addr, (char *)hp->h_addr, hp->h_length);
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
      if (!bindresvport(sock, (struct sockaddr_in *)0))
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
  return sock;
}

int verbose;

#define HASH_SHA1	0
#define HASH_SHA256	1

char *hashname[] = {"SHA1", "SHA256"};
int  hashlen[] = {20, 32};
int  hashtag[] = { RPMSIGTAG_GPG, RPMSIGTAG_PGP };
int  hashtagh[] = { RPMSIGTAG_DSA, RPMSIGTAG_RSA };
int hashalgo = HASH_SHA1;
char *timearg;
char *privkey;
int noheaderonly;

typedef union {
  SHA1_CONTEXT sha1;
  SHA256_CONTEXT sha256;
} HASH_CONTEXT;

void hash_init(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    sha1_init(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    sha256_init(&c->sha256);
}

void hash_write(HASH_CONTEXT *c, unsigned char *b, size_t l)
{
  if (hashalgo == HASH_SHA1)
    sha1_write(&c->sha1, b, l);
  else if (hashalgo == HASH_SHA256)
    sha256_write(&c->sha256, b, l);
}

void hash_final(HASH_CONTEXT *c)
{
  if (hashalgo == HASH_SHA1)
    sha1_final(&c->sha1);
  else if (hashalgo == HASH_SHA256)
    sha256_final(&c->sha256);
}

unsigned char *hash_read(HASH_CONTEXT *c)
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

char *modes[] = {"?", "rpm sign", "clear sign", "detached sign"};

void
readprivkey()
{
  FILE *fp;
  int l, ll;
  if ((fp = fopen(privkey, "r")) == 0)
    {
      perror(privkey);
      exit(1);
    }
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

int
doreq(int sock, int argc, char **argv, byte *buf, int bufl, int nret)
{
  byte *bp;
  int i, l, v, outl, errl;

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
	  return -1;
	}
      memcpy(bp, argv[i], v);
      bp += v;
    }
  v = bp - (buf + 4);
  buf[0] = v >> 8;
  buf[1] = v & 255;

  i = bp - buf;
  if (write(sock, buf, i) != i)
    {
      perror("write");
      return -1;
    }
  l = 0;
  for (;;)
    {
      int ll;
      if (l == bufl)
	{
          fprintf(stderr, "packet too big\n");
	  return -1;
	}
      ll = read(sock, buf + l, bufl - l);
      if (ll == -1)
	{
	  perror("read");
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
  if (nret)
    {
      if (outl < 2 + 2 * nret)
	{
	  fprintf(stderr, "answer too small\n");
	  return -1;
	}
      if (buf[0] != 0 || buf[1] != nret)
	{
	  fprintf(stderr, "bad answer\n");
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
getu8(byte *p)
{
  return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline int
getu8c(byte *p)
{
  if (p[0])
    {
      fprintf(stderr, "header data overflow\n");
      exit(1);
    }
  return p[1] << 16 | p[2] << 8 | p[3];
}

byte *
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

int
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

int
rpminsertsig(byte *rpmsig, int *rpmsigsizep, int *rpmsigcntp, int *rpmsigdlenp, int sigtag, byte *newsig, int newsiglen)
{
  int rpmsigsize, rpmsigcnt, rpmsigdlen;
  int i, myi, tag, off, type;
  byte *rsp;
  u32 before;
  int pad;
  byte *region = 0;

  rpmsigsize = *rpmsigsizep;
  rpmsigcnt = *rpmsigcntp;
  rpmsigdlen = *rpmsigdlenp;

  if (newsiglen > 1024)
    {
      fprintf(stderr, "signature too big: %d\n", newsiglen);
      return -1;
    }

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
  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
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
	continue;
      off = getu8c(rsp + 8);
      if (off % align == 0)
	continue;
      /* have to re-align, find end of last data */
      lastrsp = findmax(rpmsig, rpmsigcnt, off);
      lastoff = getu8c(lastrsp + 8);
      lastoff += datalen(rpmsig, rpmsigcnt, lastrsp);
      if (lastoff > off)
	{
	  fprintf(stderr, "lastoff error %d %d\n", lastoff, off);
	  return -1;
	}
      if (lastoff % align)
	lastoff += align - (lastoff % align);
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

int
sign(char *filename, int isfilter, int mode)
{
  u32 signtime;
  u32 crc;
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
  int outl, outlh, errl;
  int sock;
  int ulen;
  byte rpmlead[96];
  byte rpmsighead[16], *rsp;
  byte *rpmsig = 0;
  int rpmsigcnt = 0, rpmsigdlen = 0;
  int rpmsigsize = 0, tag;
  u32 lensig, lenhdr;
  byte rpmmd5sum[16];
  byte rpmmd5sum2[16];
  byte *hdrin_md5 = 0;
  u32 hdrin_size = 0;
  u32 rpmdataoff = 0;
  char *outfilename = 0;
  FILE *fout = 0;
  int foutfd;
  int getbuildtime = 0;
  int buildtimeoff = 0;
  byte btbuf[4];
  int gotsha1 = 0;

  if (mode == MODE_UNSET)
    {
      force = 0;
      if (isfilter)
        {
	  fprintf(stderr, "please specify a mode for filter usage.\n");
	  exit(1);
        }
      l = strlen(filename);
      if (l > 4 && (!strcmp(filename + l - 4, ".rpm") || !strcmp(filename + l - 4, ".spm")))
	mode = MODE_RPMSIGN;
      else
        mode = MODE_CLEARSIGN;
    }
  if (isfilter)
    fd = 0;
  else if ((fd = open(filename, O_RDONLY)) == -1)
    {
      perror(filename);
      exit(1);
    }
  else
    {
      outfilename = malloc(strlen(filename) + 16);
      if (!outfilename)
	{
	  fprintf(stderr, "out of memory for filename\n");
	  exit(1);
	}
      if (mode == MODE_DETACHEDSIGN)
	sprintf(outfilename, "%s.asc", filename);
      else
	sprintf(outfilename, "%s.sIgN%d", filename, getpid());
    }
  if (!timearg || mode == MODE_KEYID || mode == MODE_PUBKEY)
    signtime = (u32)time((time_t)0);
  else if (*timearg >= '0' && *timearg <= '9')
    signtime = (u32)atoi(timearg);
  else if (mode == MODE_RPMSIGN && !strcmp(timearg, "buildtime"))
    {
      getbuildtime = 1;
      signtime = (u32)0;		/* rpmsign && buildtime */
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
      signtime = (u32) stb.st_mtime;
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
	  if (tag == hashtag[hashalgo] || tag == hashtagh[hashalgo])
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

      if ((cbuf = malloc(8192)) == 0)
	{
	  fprintf(stderr, "no mem for clearsign buffer\n");
	  exit(1);
	}
      cbufl = 8192;
      l = read(fd, (char *)cbuf, cbufl);
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
      while (first || (l = read(fd, (char *)cbuf + have, cbufl - have)) > 0 || (l == 0 && have))
	{
	  first = 0;
	  if (nl)
	    hash_write(&ctx, (unsigned char *)"\r\n",  2);
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
      while ((l = read(fd, (char *)buf, sizeof(buf))) > 0)
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
	signtime = (u32)(btbuf[0] << 24 | btbuf[1] << 16 | btbuf[2] << 8 | btbuf[3]);
    }

  if (verbose && mode != MODE_KEYID && mode != MODE_PUBKEY)
    {
      if (*user)
        fprintf(isfilter ? stderr : stdout, "%s %s user %s\n", modes[mode],  filename, user);
      else
        fprintf(isfilter ? stderr : stdout, "%s %s\n", modes[mode],  filename);
    }

  hash[0] = mode == MODE_CLEARSIGN ? 0x01 : 0x00; /* class */
  hash[1] = signtime >> 24;
  hash[2] = signtime >> 16;
  hash[3] = signtime >> 8;
  hash[4] = signtime;
  hash_write(&ctx, hash, 5);
  hash_final(&ctx);
  p = hash_read(&ctx);
  ph = 0;
  outlh = 0;
  if (mode == MODE_RPMSIGN)
    {
      hash_write(&hctx, hash, 5);
      hash_final(&hctx);
      /* header only seems to work only if there's a header only hash */
      if (!noheaderonly && gotsha1)
        ph = hash_read(&hctx);
    }

  ulen = strlen(user);
  if (!privkey && !ph)
    {
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
	  bp += strlen((char *)bp);
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
      i = bp - buf;
      if (write(sock, buf, i) != i)
	{
	  perror("write");
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      l = 0;
      for (;;)
	{
	  int ll;
	  if (l == sizeof(buf))
	    {
	      fprintf(stderr, "packet too big\n");
	      exit(1);
	    }
	  ll = read(sock, buf + l, sizeof(buf) - l);
	  if (ll == -1)
	    {
	      perror("read");
	      if (mode == MODE_CLEARSIGN && !isfilter)
		unlink(outfilename);
	      exit(1);
	    }
	  if (ll == 0)
	    break;
	  l += ll;
	}
      close(sock);
      if (l < 6)
	{
	  fprintf(stderr, "packet too small\n");
	  exit(1);
	}
      outl = buf[2] << 8 | buf[3];
      errl = buf[4] << 8 | buf[5];
      if (l != outl + errl + 6)
	{
	  fprintf(stderr, "packet size mismatch %d %d %d\n", l, outl, errl);
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (errl)
	fwrite(buf + 6 + outl, 1, errl, stderr);

      if (buf[0] << 8 | buf[1])
	{
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  exit(buf[0] << 8 | buf[1]);
	}
    }
  else
    {
      char *args[5], *bp;
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
	sprintf((char *)bp, "%02x", p[i]);
      *bp++ = '@';
      for (i = 0; i < 5; i++, bp += 2)
	sprintf((char *)bp, "%02x", hash[i]);
      *bp = 0;
      if (ph)
	{
	  bp = hashhexh;
	  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	    sprintf((char *)bp, "%02x", ph[i]);
	  *bp++ = '@';
	  for (i = 0; i < 5; i++, bp += 2)
	    sprintf((char *)bp, "%02x", hash[i]);
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
      l = doreq(sock, argc, args, buf, sizeof(buf), ph ? 2 : 1);
      close(sock);
      if (l < 0)
	{
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  exit(-l);
	}
      if (buf[0] != 0 || buf[1] != (ph ? 2 : 1))
	{
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  fprintf(stderr, "bad return count\n");
	  exit(1);
	}
      outl = buf[2] << 8 | buf[3];
      outlh = ph ? (buf[4] << 8 | buf[5]) : 0;
      if (outl == 0 || (ph && outlh == 0))
	{
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  fprintf(stderr, "server returned empty signature\n");
	  exit(1);
	}
      if (l != outl + outlh + (ph ? 6 : 4))
	{
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  fprintf(stderr, "bad return length\n");
	  exit(1);
	}
      if (!ph)
        memmove(buf + 6, buf + 4, outl);
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
      else if (buf[6] == 0x90)
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
  if (isfilter)
    {
      fout = stdout;
      foutfd = 1;
    }
  else if (mode != MODE_CLEARSIGN)
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
      fprintf(fout, "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v1.0.7 (GNU/Linux)\n\n");
      printr64(fout, (byte *)buf + 6, outl);
      crc = crc24((byte *)(buf) + 6, outl);
      hash[0] = crc >> 16;
      hash[1] = crc >> 8;
      hash[2] = crc;
      putc('=', fout);
      printr64(fout, hash, 3);
      fprintf(fout, "-----END PGP SIGNATURE-----\n");
    }
  else if (mode == MODE_RPMSIGN)
    {
      if (rpminsertsig(rpmsig, &rpmsigsize, &rpmsigcnt, &rpmsigdlen, hashtag[hashalgo], buf + 6, outl))
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (outlh)
	{
	  if (rpminsertsig(rpmsig, &rpmsigsize, &rpmsigcnt, &rpmsigdlen, hashtagh[hashalgo], buf + 6 + outl, outlh))
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
      md5_init(&md5ctx);
      lensig = 0;
      while ((l = read(fd, (char *)buf, sizeof(buf))) > 0)
	{
	  md5_write(&md5ctx, buf, l);
	  xwrite(foutfd, buf, l);
	  lensig += l;
	}
      md5_final(rpmmd5sum2, &md5ctx);
      if (memcmp(rpmmd5sum2, rpmmd5sum, 16))
	{
	  fprintf(stderr, "rpm has changed, bailing out!\n");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      free(rpmsig);
    }
  else
    fwrite(buf + 6, 1, outl, fout);
  if (!isfilter)
    {
      close(fd);
      if (fclose(fout))
	{
	  perror("fclose");
	  unlink(outfilename);
	  exit(1);
	}
      if (mode != MODE_DETACHEDSIGN && rename(outfilename, filename))
	{
	  perror("rename");
	  unlink(outfilename);
	  exit(1);
	}
    }
  if (outfilename)
    free(outfilename);
  return 0;
}

void
keygen(char *type, char *expire, char *name, char *email)
{
  char *args[6];
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
      if (argc > 2 && !strcmp(argv[1], "-u"))
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
      else if (argc > 1 && !strcmp(argv[1], "-r"))
	{
	  mode = MODE_RPMSIGN;
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
      else if (argc > 1 && !strcmp(argv[1], "--"))
        {
	  argc--;
	  argv++;
	  break;
        }
      else if (argc > 1 && argv[1][0] == '-')
	{
	  fprintf(stderr, "usage: sign [-c|-d|-r] [-u user] <file>\n");
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
      fprintf(stderr, "usage: sign [-c|-d|-r] [-u user] <file>\n");
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
  if (privkey && access(privkey, R_OK))
    {
      perror(privkey);
      exit(1);
    }
  if (argc == 1)
    sign("<stdin>", 1, mode);
  else while (argc > 1)
    {
      sign(argv[1], 0, mode);
      argv++;
      argc--;
    }
  exit(0);
}

