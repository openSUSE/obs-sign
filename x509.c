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

static byte cert_version_3[] = { 0x05, 0xa0, 0x03, 0x02, 0x01, 0x02 };
static byte oid_common_name[] = { 0x05, 0x06, 0x03, 0x55, 0x04, 0x03 };
static byte oid_email_address[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 };
static byte oid_rsa_encryption[] = { 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

static byte sig_algo_rsa_sha256[] = { 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };

static byte subject_key_identifier[] = { 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static byte authority_key_identifier[] = { 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static byte basic_constraints[] = { 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00 };
static byte key_usage[] = { 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x84 };
static byte ext_key_usage[] = { 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };

static void
certbuf_room(struct certbuf *cb, int l)
{
  if (l < 0 || l > 100000 || cb->len > 100000)
    abort();
  if (cb->len + l > cb->alen)
    {
      cb->alen = cb->len + l + 256;
      if (cb->buf)
        cb->buf = realloc(cb->buf, cb->alen);
      else
        cb->buf = malloc(cb->alen);
      if (!cb->buf)
	{
	  fprintf(stderr, "out of certbuf memory\n");
	  exit(1);
	}
    }
}

static void
certbuf_add(struct certbuf *cb, byte *blob, int blobl)
{
  certbuf_room(cb, blobl);
  if (blob)
    memmove(cb->buf + cb->len, blob, blobl);
  else
    memset(cb->buf + cb->len, 0, blobl);
  cb->len += blobl;
}

static void
certbuf_insert(struct certbuf *cb, int offset, byte *blob, int blobl)
{
  if (offset < 0 || offset > cb->len)
    abort();
  certbuf_room(cb, blobl);
  if (offset < cb->len)
    memmove(cb->buf + offset + blobl, cb->buf + offset, cb->len - offset);
  if (blob)
    memmove(cb->buf + offset, blob, blobl);
  else
    memset(cb->buf + offset, 0, blobl);
  cb->len += blobl;
}

static void
certbuf_tag(struct certbuf *cb, int offset, int tag)
{
  int ll, l = cb->len - offset;
  if (l < 0 || l >= 0x1000000)
    abort();
  ll = l < 0x80 ? 0 : l < 0x100 ? 1 : l < 0x10000 ? 2 : 3;
  certbuf_insert(cb, offset, 0, 2 + ll);
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
certbuf_time(struct certbuf *cb, time_t t)
{
  int offset = cb->len;
  struct tm *tm = gmtime(&t);
  char tbuf[256];
  sprintf(tbuf, "%04d%02d%02d%02d%02d%02dZ", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  if (tm->tm_year >= 50 && tm->tm_year < 150)
    {
      certbuf_add(cb, (byte *)tbuf + 2, strlen(tbuf + 2));
      certbuf_tag(cb, offset, 0x17);
    }
  else
    {
      certbuf_add(cb, (byte *)tbuf, strlen(tbuf));
      certbuf_tag(cb, offset, 0x18);
    }
}

static void
certbuf_random_serial(struct certbuf *cb)
{
  int offset = cb->len;
  int i;
  certbuf_add(cb, 0, 9);
  for (i = 1; i < 9; i++)
    cb->buf[offset + i] = (byte)random();
  cb->buf[offset] = 0;
  cb->buf[offset + 1] |= 0x80;
  certbuf_tag(cb, offset, 0x02);
}

static void
certbuf_dn(struct certbuf *cb, const char *cn, const char *email)
{
  int offset = cb->len;
  if (cn && *cn)
    {
      int offset2 = cb->len;
      certbuf_add(cb, (byte *)cn, strlen(cn));
      certbuf_tag(cb, offset2, 0x0c);
      certbuf_insert(cb, offset2, oid_common_name + 1, oid_common_name[0]);
      certbuf_tag(cb, offset2, 0x30);
      certbuf_tag(cb, offset2, 0x31);
    }
  if (email && *email)
    {
      int offset2 = cb->len;
      certbuf_add(cb, (byte *)email, strlen(email));
      for (; *email; email++)
	if (*(unsigned char *)email >= 128)
	  break;
      certbuf_tag(cb, offset2, *email ? 0x0c: 0x16);
      certbuf_insert(cb, offset2, oid_email_address + 1, oid_email_address[0]);
      certbuf_tag(cb, offset2, 0x30);
      certbuf_tag(cb, offset2, 0x31);
    }
  certbuf_tag(cb, offset, 0x30);
}

static void
certbuf_validity(struct certbuf *cb, time_t start, time_t end)
{
  int offset = cb->len;
  certbuf_time(cb, start);
  certbuf_time(cb, end);
  certbuf_tag(cb, offset, 0x30);
}

static void
certbuf_mpiint(struct certbuf *cb, byte *p, int pl)
{
  int offset = cb->len;
  while (pl && !*p)
    {
      p++;
      pl--;
    }
  if (!pl || p[0] >= 128)
    certbuf_add(cb, 0, 1);
  if (pl)
    certbuf_add(cb, p, pl);
  certbuf_tag(cb, offset, 0x02);
}

static void
certbuf_pubkey(struct certbuf *cb, byte *p, int pl, byte *e, int el, byte *keyid)
{
  int offset = cb->len;
  int offset2;
  certbuf_add(cb, oid_rsa_encryption + 1, oid_rsa_encryption[0]);
  certbuf_tag(cb, cb->len, 0x05);
  certbuf_tag(cb, offset, 0x30);
  offset2 = cb->len;
  certbuf_mpiint(cb, p, pl);
  certbuf_mpiint(cb, e, el);
  certbuf_tag(cb, offset2, 0x30);
  if (keyid)
    {
      SHA1_CONTEXT ctx;
      sha1_init(&ctx);
      sha1_write(&ctx, cb->buf + offset2, cb->len - offset2);
      sha1_final(&ctx);
      memcpy(keyid, sha1_read(&ctx), 20);
    }
  certbuf_insert(cb, offset2, 0, 1);
  certbuf_tag(cb, offset2, 0x03);
  certbuf_tag(cb, offset, 0x30);
}

static void
certbuf_extensions(struct certbuf *cb, byte *keyid)
{
  int offset = cb->len;
  /* basic contraints */
  certbuf_add(cb, basic_constraints + 1, basic_constraints[0]);
  if (keyid)
    {
      certbuf_add(cb, subject_key_identifier + 1, subject_key_identifier[0]);
      memcpy(cb->buf + cb->len - 20, keyid, 20);
      certbuf_add(cb, authority_key_identifier + 1, authority_key_identifier[0]);
      memcpy(cb->buf + cb->len - 20, keyid, 20);
    }
  certbuf_add(cb, key_usage + 1, key_usage[0]);
  certbuf_add(cb, ext_key_usage + 1, ext_key_usage[0]);
  certbuf_tag(cb, offset, 0x30);
  certbuf_tag(cb, offset, 0xa3);	/* CONT | CONS | 3 */
}

void
certbuf_tbscert(struct certbuf *cb, const char *cn, const char *email, time_t start, time_t end, byte *p, int pl, byte *e, int el)
{
  byte keyid[20];
  certbuf_add(cb, cert_version_3 + 1, cert_version_3[0]);
  certbuf_random_serial(cb);
  certbuf_add(cb, sig_algo_rsa_sha256 + 1, sig_algo_rsa_sha256[0]);
  certbuf_dn(cb, cn, email);
  certbuf_validity(cb, start, end);
  certbuf_dn(cb, cn, email);
  certbuf_pubkey(cb, p, pl, e, el, keyid);
  certbuf_extensions(cb, keyid);
  certbuf_tag(cb, 0, 0x30);
}

void
certbuf_finishcert(struct certbuf *cb, byte *sig, int sigl)
{
  certbuf_add(cb, sig_algo_rsa_sha256 + 1, sig_algo_rsa_sha256[0]);
  certbuf_add(cb, 0, 1);
  certbuf_add(cb, sig, sigl);
  certbuf_tag(cb, cb->len - (sigl + 1), 0x03);
  certbuf_tag(cb, 0, 0x30);
}

byte *
getrawopensslsig(byte *sig, int sigl, int *lenp)
{
  int pkalg, off, bytes, nbytes;
  byte *ret;

  pkalg = sig[0] == 3 ? sig[15] : sig[2];
  if (pkalg != 1)
    {
      fprintf(stderr, "Need RSA key for openssl sign\n");
      return 0;
    }
  off = findsigmpioffset(sig, sigl);
  if (sigl < off + 2)
    {
      fprintf(stderr, "truncated sig\n");
      return 0;
    }
  bytes = ((sig[off] << 8) + sig[off + 1] + 7) >> 3;
  if (sigl < off + 2 + bytes)
    {
      fprintf(stderr, "truncated sig\n");
      return 0;
    }
  /* zero pad to multiple of 16 */
  ret = malloc(bytes + 15);
  memset(ret, 0, 15);
  nbytes = (bytes + 15) & ~15;
  memcpy(ret + nbytes - bytes, sig + off + 2, bytes);
  *lenp = nbytes;
  return ret;
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
