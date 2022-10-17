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
#include <time.h>

#include "inc.h"

static const byte cert_version_3[] = { 0x05, 0xa0, 0x03, 0x02, 0x01, 0x02 };
static const byte oid_common_name[] = { 0x05, 0x06, 0x03, 0x55, 0x04, 0x03 };
static const byte oid_email_address[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 };

static const byte oid_rsa_encryption[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const byte oid_dsa_encryption[] = { 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
static const byte oid_ed25519[] = { 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };

static const byte sig_algo_rsa_sha256[] = { 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };
static const byte sig_algo_dsa_sha256[] = { 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02 };

static const byte enc_algo_rsa[] = { 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
static const byte digest_algo_sha256[] = { 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 };

static const byte subject_key_identifier[] = { 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const byte authority_key_identifier[] = { 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const byte basic_constraints[] = { 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00 };
static const byte key_usage[] = { 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x84 };
static const byte ext_key_usage[] = { 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };

static const byte oid_contenttype[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03 };
static const byte oid_messagedigest[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04 };
static const byte oid_signingtime[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05 };
static const byte oid_spc_indirect_data[] = { 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04 };

static const byte oid_spc_spopusinfo[] = { 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c };
static const byte oid_spc_statementtype[] = { 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b };
static const byte oid_ms_codesigning[] = { 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15 };
static const byte oid_pkcs7_signed_data[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };

static const byte int_1[] = { 0x03, 0x02, 0x01, 0x01 };

static const byte gpg_ed25519[] = { 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0x18 };

static void
x509_room(struct x509 *cb, int l)
{
  if (l < 0 || l > 100000 || cb->len > 100000)
    {
      fprintf(stderr, "x509_room: illegal request\n");
      exit(1);
    }
  if (cb->len + l > cb->alen)
    {
      cb->alen = cb->len + l + 256;
      if (cb->buf)
        cb->buf = realloc(cb->buf, cb->alen);
      else
        cb->buf = malloc(cb->alen);
      if (!cb->buf)
	{
	  fprintf(stderr, "out of x509 memory\n");
	  exit(1);
	}
    }
}

static void
x509_add(struct x509 *cb, const byte *blob, int blobl)
{
  x509_room(cb, blobl);
  if (blob)
    memmove(cb->buf + cb->len, blob, blobl);
  else
    memset(cb->buf + cb->len, 0, blobl);
  cb->len += blobl;
}

void
x509_insert(struct x509 *cb, int offset, const byte *blob, int blobl)
{
  if (offset < 0 || offset > cb->len)
    abort();
  x509_room(cb, blobl);
  if (offset < cb->len)
    memmove(cb->buf + offset + blobl, cb->buf + offset, cb->len - offset);
  if (blob)
    memmove(cb->buf + offset, blob, blobl);
  else
    memset(cb->buf + offset, 0, blobl);
  cb->len += blobl;
}

/* convenience */
static inline void
x509_add_const(struct x509 *cb, const byte *c)
{
  x509_add(cb, c + 1, c[0]);
}

static inline void
x509_insert_const(struct x509 *cb, int offset, const byte *c)
{
  x509_insert(cb, offset, c + 1, c[0]);
}

static void
x509_tag(struct x509 *cb, int offset, int tag)
{
  int ll, l = cb->len - offset;
  if (l < 0 || l >= 0x1000000)
    abort();
  ll = l < 0x80 ? 0 : l < 0x100 ? 1 : l < 0x10000 ? 2 : 3;
  x509_insert(cb, offset, 0, 2 + ll);
  if (ll)
    cb->buf[offset + 1] = 0x80 + ll;
  if (ll > 2)
    cb->buf[offset + ll - 1] = l >> 16;
  if (ll > 1)
    cb->buf[offset + ll] = l >> 8;
  cb->buf[offset + ll + 1] = l;
  cb->buf[offset] = tag;
}

static void
x509_tag_impl(struct x509 *cb, int offset, int tag)
{
  if (cb->len <= offset)
    return;
  cb->buf[offset] = tag | (cb->buf[offset] & 0x20);	/* keep CONS */
}

static void
x509_time(struct x509 *cb, time_t t)
{
  int offset = cb->len;
  struct tm *tm = gmtime(&t);
  char tbuf[256];
  sprintf(tbuf, "%04d%02d%02d%02d%02d%02dZ", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  if (tm->tm_year >= 50 && tm->tm_year < 150)
    {
      x509_add(cb, (byte *)tbuf + 2, strlen(tbuf + 2));
      x509_tag(cb, offset, 0x17);
    }
  else
    {
      x509_add(cb, (byte *)tbuf, strlen(tbuf));
      x509_tag(cb, offset, 0x18);
    }
}

static void
x509_random_serial(struct x509 *cb)
{
  int offset = cb->len;
  int i;
  x509_add(cb, 0, 20);
  for (i = 0; i < 20; i++)
    cb->buf[offset + i] = (byte)random();
  cb->buf[offset] &= 0x3f;
  cb->buf[offset] |= 0x40;
  x509_tag(cb, offset, 0x02);
}

static void
x509_dn(struct x509 *cb, const char *cn, const char *email)
{
  int offset = cb->len;
  if (cn && *cn)
    {
      int offset2 = cb->len;
      x509_add(cb, (byte *)cn, strlen(cn));
      x509_tag(cb, offset2, 0x0c);
      x509_insert_const(cb, offset2, oid_common_name);
      x509_tag(cb, offset2, 0x30);
      x509_tag(cb, offset2, 0x31);
    }
  if (email && *email)
    {
      int offset2 = cb->len;
      x509_add(cb, (byte *)email, strlen(email));
      for (; *email; email++)
	if (*(unsigned char *)email >= 128)
	  break;
      x509_tag(cb, offset2, *email ? 0x0c: 0x16);
      x509_insert_const(cb, offset2, oid_email_address);
      x509_tag(cb, offset2, 0x30);
      x509_tag(cb, offset2, 0x31);
    }
  x509_tag(cb, offset, 0x30);
}

static void
x509_validity(struct x509 *cb, time_t start, time_t end)
{
  int offset = cb->len;
  x509_time(cb, start);
  x509_time(cb, end);
  x509_tag(cb, offset, 0x30);
}

static void
x509_mpiint(struct x509 *cb, byte *p, int pl)
{
  int offset = cb->len;
  while (pl && !*p)
    {
      p++;
      pl--;
    }
  if (!pl || p[0] >= 128)
    x509_add(cb, 0, 1);
  if (pl)
    x509_add(cb, p, pl);
  x509_tag(cb, offset, 0x02);
}

static void
x509_pubkey(struct x509 *cb, int pubalgo, byte **mpi, int *mpil, byte *keyid)
{
  int offset = cb->len, offset2;
  if (pubalgo == PUB_RSA)
    {
      x509_add_const(cb, oid_rsa_encryption);
      x509_tag(cb, cb->len, 0x05);	/* NULL */
    }
  else if (pubalgo == PUB_DSA)
    {
      x509_add_const(cb, oid_dsa_encryption);
      offset2 = cb->len;
      x509_mpiint(cb, mpi[0], mpil[0]);
      x509_mpiint(cb, mpi[1], mpil[1]);
      x509_mpiint(cb, mpi[2], mpil[2]);
      x509_tag(cb, offset2, 0x30);
    }
  else if (pubalgo == PUB_EDDSA)
    {
      if (mpil[0] == gpg_ed25519[0] && !memcmp(mpi[0], gpg_ed25519 + 1, mpil[0]))
	x509_add_const(cb, oid_ed25519);
      else
	{
	  fprintf(stderr, "x509_pubkey: unsupported EdDSA curve\n");
	  exit(1);
	}
    }
  else
    {
      fprintf(stderr, "x509_pubkey: unsupported pubkey algorithm %d\n", pubalgo);
      exit(1);
    }
  x509_tag(cb, offset, 0x30);
  offset2 = cb->len;
  if (pubalgo == PUB_RSA)
    {
      x509_mpiint(cb, mpi[0], mpil[0]);
      x509_mpiint(cb, mpi[1], mpil[1]);
      x509_tag(cb, offset2, 0x30);
    }
  else if (pubalgo == PUB_DSA)
    x509_mpiint(cb, mpi[3], mpil[3]);
  else if (pubalgo == PUB_EDDSA)
    {
      if (mpil[1] < 2 || mpi[1][0] != 0x40)
	{
	  fprintf(stderr, "x509_pubkey: bad EdDSA point\n");
	  exit(1);
	}
      x509_add(cb, mpi[1] + 1, mpil[1] - 1);
    }
  if (keyid)
    {
      SHA1_CONTEXT ctx;
      sha1_init(&ctx);
      sha1_write(&ctx, cb->buf + offset2, cb->len - offset2);
      sha1_final(&ctx);
      memcpy(keyid, sha1_read(&ctx), 20);
    }
  x509_insert(cb, offset2, 0, 1);
  x509_tag(cb, offset2, 0x03);
  x509_tag(cb, offset, 0x30);
}

static void
x509_extensions(struct x509 *cb, byte *keyid)
{
  int offset = cb->len;
  /* basic contraints */
  x509_add_const(cb, basic_constraints);
  if (keyid)
    {
      x509_add_const(cb, subject_key_identifier);
      memcpy(cb->buf + cb->len - 20, keyid, 20);
      x509_add_const(cb, authority_key_identifier);
      memcpy(cb->buf + cb->len - 20, keyid, 20);
    }
  x509_add(cb, key_usage + 1, key_usage[0]);
  x509_add_const(cb, ext_key_usage);
  x509_tag(cb, offset, 0x30);
  x509_tag(cb, offset, 0xa3);	/* CONT | CONS | 3 */
}

static void
x509_add_sigalgo(struct x509 *cb, int pubalgo)
{
  if (pubalgo == PUB_RSA && hashalgo == HASH_SHA256)
    x509_add_const(cb, sig_algo_rsa_sha256);
  else if (pubalgo == PUB_DSA && hashalgo == HASH_SHA256)
    x509_add_const(cb, sig_algo_dsa_sha256);
  else
    {
      fprintf(stderr, "unsupported pubalgo/hashalgo combination: %d/%d\n", pubalgo, hashalgo);
      exit(1);
    }
}

void
x509_tbscert(struct x509 *cb, const char *cn, const char *email, time_t start, time_t end, int pubalgo, byte **mpi, int *mpil)
{
  int offset = cb->len;
  byte keyid[20];
  x509_add_const(cb, cert_version_3);
  x509_random_serial(cb);
  x509_add_sigalgo(cb, pubalgo);
  x509_dn(cb, cn, email);
  x509_validity(cb, start, end);
  x509_dn(cb, cn, email);
  x509_pubkey(cb, pubalgo, mpi, mpil, keyid);
  x509_extensions(cb, keyid);
  x509_tag(cb, offset, 0x30);
}

void
x509_finishcert(struct x509 *cb, int pubalgo, byte *sig, int sigl)
{
  x509_add_sigalgo(cb, pubalgo);
  x509_add(cb, 0, 1);
  x509_add(cb, sig, sigl);
  x509_tag(cb, cb->len - (sigl + 1), 0x03);
  x509_tag(cb, 0, 0x30);
}

byte *
getrawopensslsig(byte *sig, int sigl, int *lenp)
{
  int pkalg, off, nbytes;
  byte *mpi[2];
  int mpil[2];

  pkalg = sig[0] == 3 ? sig[15] : sig[2];
  
  if (assertpubalgo == -1 && pkalg != 1)
    {
      fprintf(stderr, "Not a RSA key\n");
      return 0;
    }
  off = findsigmpioffset(sig, sigl);
  if (pkalg == 1)
    {
      setmpis(sig + off, sigl - off, 1, mpi, mpil, 0);
      /* zero pad to multiple of 16 */
      byte *ret = malloc(mpil[0] + 15);
      memset(ret, 0, 15);
      nbytes = (mpil[0] + 15) & ~15;
      memcpy(ret + nbytes - mpil[0], sig + off + 2, mpil[0]);
      *lenp = nbytes;
      return ret;
    }
  else if (pkalg == 17)
    {
      struct x509 cb;
      setmpis(sig + off, sigl - off, 2, mpi, mpil, 0);
      x509_init(&cb);
      x509_mpiint(&cb, mpi[0], mpil[0]);
      x509_mpiint(&cb, mpi[1], mpil[1]);
      x509_tag(&cb, 0, 0x30);
      *lenp = cb.len;
      return cb.buf;
    }
  else if (pkalg == 22)
    {
      fprintf(stderr, "EdDSA openssl signing is not supported\n");
      return 0;
    }
  return 0;
}

void
certsizelimit(char *s, int l)
{
  if (strlen(s) <= l)
    return;
  s += l - 4;
  for (l = 0; l < 3; l++, s--)
    if ((*s & 0xc0) != 0x80)
      break;
  strcpy(s, "...");
}

int
x509_addpem(struct x509 *cb, char *buf, char *type)
{
  int offset = cb->len;
  size_t typel = strlen(type);
  unsigned char *bp;

  while (*buf == ' ' || *buf == '\t' || *buf == '\n' || *buf == '\r')
    buf++;
  if (strncmp(buf, "-----BEGIN ", 11) != 0 || strncmp(buf + 11, type, typel) != 0 || strncmp(buf + 11 + typel, "-----\n", 6) != 0)
    return 0;
  buf += 11 + 6 + typel;
  x509_room(cb, strlen(buf) * 3 / 4 + 16);
  bp = cb->buf + offset;
  buf = r64dec(buf, &bp);
  if (!buf)
    return 0;
  while (*buf == ' ' || *buf == '\t' || *buf == '\n' || *buf == '\r')
    buf++;
  if (strncmp(buf, "-----END ", 9) != 0 || strncmp(buf + 9, type, typel) != 0 || strncmp(buf + 9 + typel, "-----\n", 6) != 0)
    return 0;
  cb->len = bp - cb->buf;
  return 1;
}

static int
x509_unpack(unsigned char *bp, int l, unsigned char **dpp, int *dlp, int *clp, int expected)
{
  unsigned char *bporig = bp;
  int tag = 0, tl = 0;
  if (l >= 2)
    {
      tag = bp[0];
      tl = bp[1];
      bp += 2;
      l -= 2;
      if (tl >= 128)
	{
	  int ll = 0;
	  tl -= 128;
	  if (tl < 1 || tl > 4)
	    {
	      fprintf(stderr, "x509_unpack: unsupported len %d\n", tl);
	      exit(1);
	    }
	  if (l < tl)
	    {
	      fprintf(stderr, "x509_unpack: EOF in len\n");
	      exit(1);
	    }
	  for (; tl > 0; tl--, l--)
	    ll = (ll << 8) + *bp++;
	  tl = ll;
	}
    }
  if (tl < 0 || tl > l)
    {
      fprintf(stderr, "x509_unpack: unexpected EOF\n");
      exit(1);
    }
  *dpp = bp;
  *dlp = tl;
  if (clp)
    *clp = bp - bporig + tl;
  if (expected && tag != expected)
    {
      fprintf(stderr, "x509_unpack: unexpeced tag %x, expected %x\n", tag, expected);
      exit(1);
    }
  return tag;
}

static int
x509_unpack_tag(unsigned char *bp, int l)
{
  return l < 2 ? 0 : bp[0];
}

static void
x509_skip(unsigned char **bpp, int *lp, int expected)
{
  unsigned char *dp;
  int dl, cl;
  x509_unpack(*bpp, *lp, &dp, &dl, &cl, expected);
  *bpp = dp + dl;
  *lp -= cl;
}

/* pkcs7 stuff
 *
 * general info: rfc2315
 * spc info: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx
 * 
 */

void
x509_spccontent(struct x509 *cb, unsigned char *digest, int digestlen)
{
  static byte spcinfodata[] = {
    0x30, 0x35, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1e, 0x30, 0x27,
    0x02, 0x04, 0x01, 0x01, 0x00, 0x00, 0x04, 0x10, 0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d,
    0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
    0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00
  };
  int offset = cb->len;

  x509_add(cb, digest, digestlen);
  x509_tag(cb, offset, 0x04);
  x509_insert_const(cb, offset, digest_algo_sha256);
  x509_tag(cb, offset, 0x30);
  x509_insert(cb, offset, spcinfodata, sizeof(spcinfodata));
}

static void
x509_issuerandserial(struct x509 *cb, unsigned char *cert, int certlen)
{
  int offset = cb->len;
  unsigned char *dp;
  int dl, cl;
  unsigned char *serial;
  int seriallen;

  x509_unpack(cert, certlen, &cert, &certlen, 0, 0x30);
  x509_unpack(cert, certlen, &cert, &certlen, 0, 0x30);
  if (x509_unpack_tag(cert, certlen) == 0xa0)
    x509_skip(&cert, &certlen, 0xa0);	/* skip version */
  x509_unpack(cert, certlen, &dp, &dl, &cl, 0x02);
  serial = cert;
  seriallen = cl;
  cert = dp + dl;
  certlen -= cl;
  x509_skip(&cert, &certlen, 0x30);	/* skip signature algorithm */
  x509_unpack(cert, certlen, &dp, &dl, &cl, 0x30);
  x509_add(cb, cert, cl);
  x509_add(cb, serial, seriallen);
  x509_tag(cb, offset, 0x30);
}

void
x509_spcsignedattrs(struct x509 *cb, unsigned char *digest, int digestlen, time_t signtime)
{
  int offset = cb->len, offset2;

  /* opusinfo attribute */
  offset2 = cb->len;
  x509_tag(cb, offset2, 0x30);
  x509_tag(cb, offset2, 0x31);
  x509_insert_const(cb, offset2, oid_spc_spopusinfo);
  x509_tag(cb, offset2, 0x30);
  /* contenttype attribute */
  offset2 = cb->len;
  x509_add_const(cb, oid_spc_indirect_data);
  x509_tag(cb, offset2, 0x31);
  x509_insert_const(cb, offset2, oid_contenttype);
  x509_tag(cb, offset2, 0x30);
  /* signingtime attribute */
  if (signtime)
    {
      offset2 = cb->len;
      x509_time(cb, signtime);
      x509_tag(cb, offset2, 0x31);
      x509_insert_const(cb, offset2, oid_signingtime);
      x509_tag(cb, offset2, 0x30);
    }
  /* statementtype attribute */
  offset2 = cb->len;
  x509_add_const(cb, oid_ms_codesigning);
  x509_tag(cb, offset2, 0x30);
  x509_tag(cb, offset2, 0x31);
  x509_insert_const(cb, offset2, oid_spc_statementtype);
  x509_tag(cb, offset2, 0x30);
  /* message digest attribute */
  offset2 = cb->len;
  x509_add(cb, digest, digestlen);
  x509_tag(cb, offset2, 0x04);
  x509_tag(cb, offset2, 0x31);
  x509_insert_const(cb, offset2, oid_messagedigest);
  x509_tag(cb, offset2, 0x30);
  /* return a set */
  x509_tag(cb, offset, 0x31);
}

static void
x509_signerinfo(struct x509 *cb, struct x509 *signedattrs, struct x509 *cert, unsigned char *sig, int siglen)
{
  int offset = cb->len, offset2;
  x509_add_const(cb, int_1);	/* version 1 */
  /* issuer and serial number */
  x509_issuerandserial(cb, cert->buf, cert->len);
  x509_add_const(cb, digest_algo_sha256);
  offset2 = cb->len;
  x509_add(cb, signedattrs->buf, signedattrs->len);
  x509_tag_impl(cb, offset2, 0xa0);	/* CONT | CONS | 0 */
  x509_add_const(cb, enc_algo_rsa);
  offset2 = cb->len;
  x509_add(cb, sig, siglen);
  x509_tag(cb, offset2, 0x04);
  x509_tag(cb, offset, 0x30);
}

static int
x509_identicalcert(struct x509 *cert, unsigned char *cert2, int cert2len)
{
  int offset, r;
  struct x509 cb;
  x509_init(&cb);
  x509_issuerandserial(&cb, cert->buf, cert->len);
  offset = cb.len;
  x509_issuerandserial(&cb, cert2, cert2len);
  r = cb.len == 2 * offset && memcmp(cb.buf, cb.buf + offset, offset) == 0;
  x509_free(&cb);
  return r;
}

static void
x509_add_othercerts(struct x509 *cb, struct x509 *cert, struct x509 *othercerts)
{
  unsigned char *bp = othercerts->buf;
  int l = othercerts->len;
  while (l > 0)
    {
      unsigned char *dp;
      int dl, cl;
      x509_unpack(bp, l, &dp, &dl, &cl, 0x30);
      if (!x509_identicalcert(cert, bp, cl))
	x509_add(cb, bp, cl);
      bp += cl;
      l -= cl;
    }
}

void
x509_pkcs7(struct x509 *cb, struct x509 *content, struct x509 *signedattrs, unsigned char *sig, int siglen, struct x509 *cert, struct x509 *othercerts)
{
  int offset = cb->len, offset2;
  x509_add_const(cb, digest_algo_sha256);
  x509_tag(cb, offset, 0x31);
  x509_insert_const(cb, offset, int_1);
  /* contentinfo */
  offset2 = cb->len;
  x509_add(cb, content->buf, content->len);
  x509_tag(cb, offset2, 0x30);
  x509_tag(cb, offset2, 0xa0);	/* CONT | CONS | 0 */
  x509_insert_const(cb, offset2, oid_spc_indirect_data);
  x509_tag(cb, offset2, 0x30);
  /* certs */
  offset2 = cb->len;
  x509_add(cb, cert->buf, cert->len);
  if (othercerts)
    x509_add_othercerts(cb, cert, othercerts);
  x509_tag(cb, offset2, 0xa0);	/* CONT | CONS | 0 */
  /* signerinfos */
  offset2 = cb->len;
  x509_signerinfo(cb, signedattrs, cert, sig, siglen);
  x509_tag(cb, offset2, 0x31);
  /* finish */
  x509_tag(cb, offset, 0x30);
  x509_tag(cb, offset, 0xa0);	/* CONT | CONS | 0 */
  x509_insert_const(cb, offset, oid_pkcs7_signed_data);
  x509_tag(cb, offset, 0x30);
}
