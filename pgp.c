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
  u32 v;

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
  buf = doalloc(l * 3 / 4 + 4 + 16);
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
static const int  pubpgpalgo[] = {17, 1, 22, 19};

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

static unsigned char
v4sig_skel_fpv4[] = {
  0x04,		/* version */
  0x00, 	/* type */
  0x00,		/* pubalgo */
  0x00,		/* hashalgo */
  0x00, 0x1d, 	/* octet count hashed */
  0x16, 0x21, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x05, 0x02, 0x00, 0x00, 0x00, 0x00,	/* sig created subpkg */
  0x00, 0x0a, 	/* octet count unhashed */
  0x09, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* issuer subpkg */
};

static unsigned char
v3sig_skel[] = {
  0x03,		/* version */
  0x05,		/* size of hashed data */
  0x00, 	/* type */
  0x00, 0x00, 0x00, 0x00,	/* sig created */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* issuer */
  0x00, 	/* pubalgo */
  0x00, 	/* hashalgo */
};

#define V4SIG_HASHED (4 + 2 + 6)
#define V4SIG_HASHED_FPV4 (4 + 2 + 29)

unsigned char *
genv4sigtrail(int clearsign, int pubalgo, int hashalgo, u32 signtime, unsigned char *fp, int *v4sigtraillen)
{
  int hlen;
  unsigned char *v4sigtrail;
  if (fp && fp[0] != 4)
    fp = 0;	/* sorry, only v4 supported */
  hlen = fp ? V4SIG_HASHED_FPV4 : V4SIG_HASHED;
  v4sigtrail = doalloc(hlen + 6);
  memcpy(v4sigtrail, fp ? v4sig_skel_fpv4 : v4sig_skel, hlen);
  v4sigtrail[1] = clearsign ? 0x01 : 0x00;
  v4sigtrail[2] = pubpgpalgo[pubalgo];
  v4sigtrail[3] = hashpgpalgo[hashalgo];
  if (fp)
    memcpy(v4sigtrail + 8, fp, 20 + 1);
  v4sigtrail[hlen - 4] = signtime >> 24;
  v4sigtrail[hlen - 3] = signtime >> 16;
  v4sigtrail[hlen - 2] = signtime >> 8;
  v4sigtrail[hlen - 1] = signtime;
  v4sigtrail[hlen ] = 4;
  v4sigtrail[hlen + 1] = 255;
  v4sigtrail[hlen + 2] = 0;
  v4sigtrail[hlen + 3] = 0;
  v4sigtrail[hlen + 4] = hlen >> 8;
  v4sigtrail[hlen + 5] = hlen;
  *v4sigtraillen = hlen + 6;
  return v4sigtrail;
}

static int
fixupsig_fin(unsigned char *sigpk, int sigpklen, int tail, int left, unsigned char *newsig, int newsiglen, unsigned char *mpidata, int mpidatalen)
{
  int nhl, nl = newsiglen + mpidatalen;
  if (mpidatalen < 2)
    dodie("fixupsig: mpidatalen is too small");
  if (nl >= 65536)
    dodie("fixupsig: new signature is too big");
  if (sigpk + sigpklen != mpidata + mpidatalen)
    dodie("fixupsig: trailing signature data");
  memmove(sigpk + left, sigpk, sigpklen + tail);		/* make room, also moves mpidata */
  if (nl < 256)
    {
      sigpk[0] = 0x88;
      sigpk[1] = nl;
      nhl = 2;
    }
  else
    {
      sigpk[0] = 0x89;
      sigpk[1] = nl >> 8;
      sigpk[2] = nl;
      nhl = 3;
    }
  if (nhl + nl >= sigpklen + left)
    dodie("fixupsig: no room left");
  memmove(sigpk + nhl, newsig, newsiglen);
  memmove(sigpk + nhl + newsiglen, mpidata + left, mpidatalen);
  if (tail)
    memmove(sigpk + nhl + nl, sigpk + left + sigpklen, tail);
  return nhl + nl;
}

int
fixupsig(unsigned char *sigtrail, unsigned char *v4sigtrail, unsigned char *sigpk, int sigpklen, int tail, int left)
{
  unsigned char *sig, *issuer;
  int sigl, mpioff, alg = 0, halg = 0;

  sig = pkg2sig(sigpk, sigpklen, &sigl);

  if (sig[0] == 3 && !v4sigtrail && sigl >= 19)
    {
      memcpy(sig + 2, sigtrail, 5);	/* all is fine, just patch in sigtrail data */
      return sigpklen;
    }

  if (sig[0] == 3)
    {
      alg = sig[15];
      halg = sig[16];
    }
  else if (sig[0] == 4)
    {
      alg = sig[2];
      halg = sig[3];
    }
  else
    dodie("unsupported signature version");
  issuer = findsigissuer(sig, sigl);
  if (!issuer)
    dodie("could not determine issuer");
  mpioff = findsigmpioffset(sig, sigl) - 2;

  if (v4sigtrail && v4sigtrail[5] == 0x1d)
    {
      unsigned char newsig4[sizeof(v4sig_skel_fpv4)];
      /* we want a v4 sig with a v4 fingerprint */
      if (alg != v4sigtrail[2])
	{
	  fprintf(stderr, "v3tov4 pubkey algo mismatch: %d != %d\n", alg, v4sigtrail[2]);
	  exit(1);
	}
      if (halg != v4sigtrail[3])
	dodie("fixupsig hash algo mismatch");
      memcpy(newsig4, v4sig_skel_fpv4, sizeof(v4sig_skel_fpv4));
      memcpy(newsig4, v4sigtrail, V4SIG_HASHED_FPV4);		/* patch sigtrail data */
      memcpy(newsig4 + V4SIG_HASHED_FPV4 + 4, issuer, 8);	/* patch issuer */
      return fixupsig_fin(sigpk, sigpklen, tail, left, newsig4, sizeof(newsig4), sig + mpioff, sigl - mpioff);
    }
  else if (v4sigtrail)
    {
      unsigned char newsig4[sizeof(v4sig_skel)];
      /* we want a v4 sig */
      if (alg != v4sigtrail[2])
	{
	  fprintf(stderr, "v3tov4 pubkey algo mismatch: %d != %d\n", alg, v4sigtrail[2]);
	  exit(1);
	}
      if (halg != v4sigtrail[3])
	dodie("fixupsig hash algo mismatch");
      memcpy(newsig4, v4sig_skel, sizeof(v4sig_skel));
      memcpy(newsig4, v4sigtrail, V4SIG_HASHED);		/* patch sigtrail data */
      memcpy(newsig4 + V4SIG_HASHED + 4, issuer, 8);		/* patch issuer */
      return fixupsig_fin(sigpk, sigpklen, tail, left, newsig4, sizeof(newsig4), sig + mpioff, sigl - mpioff);
    }
  else
    {
      unsigned char newsig3[sizeof(v3sig_skel)];
      /* we want a v3 sig */
      memcpy(newsig3, v3sig_skel, sizeof(v3sig_skel));
      memcpy(newsig3 + 2, sigtrail, 5);		/* patch sigtrail data */
      memcpy(newsig3 + 7, issuer, 8);		/* patch issuer */
      newsig3[15] = alg;
      newsig3[16] = halg;
      return fixupsig_fin(sigpk, sigpklen, tail, left, newsig3, sizeof(newsig3), sig + mpioff, sigl - mpioff);
    }
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
      if (pl < l || (l == 4 && p[0] != 0))
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
	  if (pl <= 4 || p[0] != 0)
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
findsubpkg(unsigned char *q, int l, int type, int *slp, int fixedsl)
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
	  if (ql < 4 || q[0] != 0)
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
      if (sl == 0 || ql < sl)
	return 0;
      x = q[0] & 127;
      if (x == type && (fixedsl < 0 || sl - 1 == fixedsl))
	{
	  if (slp)
	    *slp = sl - 1;
	  return q + 1;
	}
      q += sl;
      ql -= sl;
    }
  return 0;
}

unsigned char *
addpkg(unsigned char *to, unsigned char *p, int l, int tag, int newformat)
{
  if (l < 0 || l >= 8192)
    abort();
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
	dodie("signature packet is too small");
      ll += 2 + (sig[ll] << 8) + sig[ll + 1];
      if (l < ll + 2)
	dodie("signature packet is too small");
      ll += 2 + (sig[ll] << 8) + sig[ll + 1];
    }
  else
    dodie("not a V3 or V4 signature");
  if (l < ll + 2)
    dodie("signature packet is too small");
  *siglp = l;
  return sig;
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
  issuer = findsubpkg(sig + 4, sigl - 4, 16, 0, 8);
  if (issuer)
    return issuer;
  hl = 4 + 2 + ((sig[4] << 8) | sig[5]);
  return findsubpkg(sig + hl, sigl - hl, 16, 0, 8);
}

int
findsigmpioffset(byte *sig, int sigl)
{
  if (sig[0] == 3)
    return 19;
  if (sig[0] == 4)
    {
      int off = 6 + (sig[4] << 8) + sig[5];
      off += 2 + (sig[off] << 8) + sig[off + 1] + 2;
      return off;
    }
  dodie("not a v3 or v4 signature");
  return -1;
}

int
findsigpubalgo(byte *sig, int sigl)
{
  int algo = -1;
  if (sig[0] == 3)
    algo = sig[15];
  else if (sig[0] == 4)
    algo = sig[2];
  if (algo == 1)
    return PUB_RSA;
  if (algo == 17)
    return PUB_DSA;
  if (algo == 19)
    return PUB_ECDSA;
  if (algo == 22)
    return PUB_EDDSA;
  return -1;
}

int
pkg2sigpubalgo(byte *pk, int pkl)
{
  int sigl;
  byte *sig = pkg2sig(pk, pkl, &sigl);
  return findsigpubalgo(sig, sigl);
}

void
calculatekeyfingerprint(byte *key, int keyl, byte *fingerprintp)
{
  byte b[3];
  if (!keyl || *key != 4)
    dodie("only know how to calculate the fingerprint of V4 keys");
  SHA1_CONTEXT ctx;
  sha1_init(&ctx);
  b[0] = 0x99;
  b[1] = keyl >> 8;
  b[2] = keyl;
  sha1_write(&ctx, b, 3);
  sha1_write(&ctx, key, keyl);
  sha1_final(&ctx);
  memcpy(fingerprintp, sha1_read(&ctx), 20);
}

int
findkeypubalgo(byte *key, int keyl)
{
  int algo = -1;
  if (keyl >= 8 && key[0] == 3)
    algo = key[7];
  else if (keyl >= 6 && key[0] == 4)
    algo = key[5];
  if (algo == 1)
    return PUB_RSA;
  if (algo == 17)
    return PUB_DSA;
  if (algo == 19)
    return PUB_ECDSA;
  if (algo == 22)
    return PUB_EDDSA;
  return -1;
}

int
findkeympioffset(byte *key, int keyl)
{
  if (keyl >= 8 && key[0] == 3)
    return 8;
  if (keyl >= 6 && key[0] == 4)
    return 6;
  dodie("not a v3 or v4 key");
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
	dodie("truncated mpi data");
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
	dodie("truncated mpi data");
      *mpi++ = p;
      *mpil++ = bytes;
      p += bytes;
      l -= bytes;
    }
  return origl - l;
}

