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

#include <stdlib.h>
#include <string.h>

#include "inc.h"

/* armor handling */

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
write_crc(FILE *fp, const byte *buf, int length)
{
  byte hash[3];
  u32 crc = crc24(buf, length);
  hash[0] = crc >> 16;
  hash[1] = crc >> 8;
  hash[2] = crc; 
  putc('=', fp); 
  printr64(fp, hash, 3);
}

void
write_armored_signature(FILE *fp, const byte *signature, int length)
{
  fprintf(fp, "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v1.0.7 (GNU/Linux)\n\n");
  printr64(fp, signature, length);
  write_crc(fp, signature, length);
  fprintf(fp, "-----END PGP SIGNATURE-----\n");
}

void
write_armored_pubkey(FILE *fp, const byte *pubkey, int length)
{
  printf("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1.4.5 (GNU/Linux)\n\n");
  printr64(fp, pubkey, length);
  write_crc(fp, pubkey, length);
  fprintf(fp, "-----END PGP PUBLIC KEY BLOCK-----\n");
}

char *
get_armored_signature(const byte *signature, int length)
{
  char *ret = 0;
  size_t size;
  FILE *fp = open_memstream(&ret, &size);
  write_armored_signature(fp, signature, length);
  fclose(fp);
  return ret;
}

unsigned char *
unarmor_pubkey(char *pubkey, int *pktlp)
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
  buf = malloc(l * 3 / 4 + 4 + 16);
  bp = buf;
  pubkey = r64dec(pubkey, &bp);
  if (!pubkey)
    {
      free(buf);
      return 0;
    }
  while (*pubkey == ' ' || *pubkey == '\t' || *pubkey == '\n' || *pubkey == '\r')
    pubkey++;
  eof = 0;
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


/* v4 signature support */

static const int  hashpgpalgo[] = {2, 8, 10};
static const int  pubpgpalgo[] = {17, 1, 22};

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

unsigned char *
genv4sigtrail(int clearsign, int pubalgo, int hashalgo, u32 signtime, int *v4sigtraillen)
{
  unsigned char *v4sigtrail = malloc(V4SIG_HASHED + 6);
  memcpy(v4sigtrail, v4sig_skel, V4SIG_HASHED);
  v4sigtrail[1] = clearsign ? 0x01 : 0x00;
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

int
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
  else if (v3sig[0] == 0xc2 && (v3sig[1] < 224 || v3sig[1] == 255))
    {
      o = 2;
      if (v3sig[1] >= 192 && v3sig[1] < 224)
        o = 3;
      if (v3sig[1] == 255)
        o = 5;
    }
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

unsigned char *
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

unsigned char *
findsubpkg(unsigned char *q, int l, int type)
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

unsigned char *
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

byte *
pkg2sig(byte *pk, int pkl, int *siglp)
{
  byte *sig;
  int l, ll, tag = 0;
  sig = nextpkg(&tag, &l, &pk, &pkl);
  if (!sig || l < 6 || tag != 2)
    {
      fprintf(stderr, "packet is not a signature [%d]\n", tag);
      exit(1);
    }
  if (sig[0] == 3)
    ll = 19;
  else if (sig[0] == 4)
    {
      int ll = 4;
      if (l < ll + 2)
	{
	  fprintf(stderr, "signature packet is too small\n");
	  exit(1);
	}
      ll += 2 + (sig[ll] << 8) + sig[ll + 1];
      if (l < ll + 2)
	{
	  fprintf(stderr, "signature packet is too small\n");
	  exit(1);
	}
      ll += 2 + (sig[ll] << 8) + sig[ll + 1];
    }
  else
    {
      fprintf(stderr, "not a V3 or V4 signature\n");
      exit(1);
    }
  if (l < ll + 2)
    {
      fprintf(stderr, "signature packet is too small\n");
      exit(1);
    }
  *siglp = l;
  return sig;
}

void
calculatefingerprint(byte *pub, int publ, byte *fingerprintp)
{
  byte b[3];
  if (!publ || *pub != 4)
    {
      fprintf(stderr, "only know how to calculate the fingerprint of V4 keys\n");
      exit(1);
    }
  SHA1_CONTEXT ctx;
  sha1_init(&ctx);
  b[0] = 0x99;
  b[1] = publ >> 8;
  b[2] = publ;
  sha1_write(&ctx, b, 3);
  sha1_write(&ctx, pub, publ);
  sha1_final(&ctx);
  memcpy(fingerprintp, sha1_read(&ctx), 20);
}

byte *
findsigissuer(byte *sig, int sigl)
{
  byte *issuer;
  int hl;

  if (!sigl)
    return 0;
  if (sig[0] == 3)
    return sigl >= 15 ? sig + 7 : 0;
  if (sig[0] != 4)
    return 0;
  issuer = findsubpkg(sig + 4, sigl - 4, 16);
  if (issuer)
    return issuer;
  hl = 4 + 2 + ((sig[4] << 8) | sig[5]);
  return findsubpkg(sig + hl, sigl - hl, 16);
}

int
findsigmpioffset(byte *sig, int sigl)
{
  int off;
  if (sig[0] == 3)
    return 19;
  if (sig[0] != 4)
    abort();
  off = 6 + (sig[4] << 8) + sig[5];
  off += 2 + (sig[off] << 8) + sig[off + 1] + 2;
  return off;
}

int
findsigpubalgo(byte *pk, int pkl)
{
  int sigl, algo = -1;
  byte *sig = pkg2sig(pk, pkl, &sigl);
  if (sig[0] == 3)
    algo = sig[15];
  else if (sig[0] == 4)
    algo = sig[2];
  if (algo == 1)
    return PUB_RSA;
  if (algo == 17)
    return PUB_DSA;
  if (algo == 22)
    return PUB_EDDSA;
  return -1;
}

int
setmpis(byte *p, int l, int nmpi, byte **mpi, int *mpil, int withcurve)
{
  int origl = l;
  for (; nmpi > 0; nmpi--)
    {
      int bytes;
      if (l < 2)
	{
	  fprintf(stderr, "truncated mpi data\n");
	  exit(1);
	}
      if (withcurve)
	{
	  withcurve = 0;
	  bytes = p[0];
	  if (bytes == 0 || bytes == 255)
	    {
	      fprintf(stderr, "illegal curve length: %d\n", bytes);
	      exit(1);
	    }
	  p++;
	  l--;
	}
      else
	{
	  bytes = ((p[0] << 8) + p[1] + 7) >> 3;
	  p += 2;
	  l -= 2;
	}
      if (l < bytes)
	{
	  fprintf(stderr, "truncated mpi data\n");
	  exit(1);
	}
      *mpi++ = p;
      *mpil++ = bytes;
      p += bytes;
      l -= bytes;
    }
  return origl - l;
}

