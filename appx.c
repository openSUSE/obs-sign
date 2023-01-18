/*
 * Copyright (c) 2019 SUSE LLC
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

static void
dohash(int fd, u64 size, unsigned char *out)
{
  unsigned char buf[65536];
  HASH_CONTEXT ctx;

  hash_init(&ctx);
  while (size > 0)
    {
      int chunk = size > sizeof(buf) ? sizeof(buf) : size;
      doread(fd, buf, chunk);
      hash_write(&ctx, buf, chunk);
      size -= chunk;
    }
  hash_final(&ctx);
  memcpy(out, hash_read(&ctx), hash_len());
}

static u32
hashfileentry(struct zip *zip, int fd, char *fn, unsigned char *out)
{
  unsigned char *entry;
  u64 datasize;

  entry = zip_findentry(zip, fn);
  if (!entry)
    {
      fprintf(stderr, "missing '%s' file", fn);
      exit(1);
    }
  datasize = zip_seekdata(zip, fd, entry);
  dohash(fd, datasize, out);
  return zip_entry_datetime(entry);
}

static int
appx_create_contentinfo(struct appxdata *appxdata, int fd)
{
  static const unsigned char axmgsig[4] = { 0x41, 0x50, 0x50, 0x58 };
  static const unsigned char axpcsig[4] = { 0x41, 0x58, 0x50, 0x43 };
  static const unsigned char axcdsig[4] = { 0x41, 0x58, 0x43, 0x44 };
  static const unsigned char axctsig[4] = { 0x41, 0x58, 0x43, 0x54 };
  static const unsigned char axbmsig[4] = { 0x41, 0x58, 0x42, 0x4d };
  static const unsigned char axcisig[4] = { 0x41, 0x58, 0x43, 0x49 };
  unsigned char *digest, *dp;
  int hlen = hash_len();
  int offset;

  /* rewind */
  doseek(fd, 0);

  /* create digest space */
  digest = doalloc(4 + (4 + hlen) * 5);
  memset(digest, 0, 4 + (4 + hlen) * 5);

  /* add magic */
  memcpy(digest, axmgsig, 4);
  dp = digest + 4;

  /* hash from start to central dir */
  memcpy(dp, axpcsig, 4);
  dohash(fd, appxdata->zip.cd_offset, dp + 4);
  dp += 4 + hlen;

  /* hash from central dir to end */
  memcpy(dp, axcdsig, 4);
  dohash(fd, appxdata->zip.size - appxdata->zip.cd_offset, dp + 4);
  dp += 4 + hlen;

  /* hash content types */
  memcpy(dp, axctsig, 4);
  appxdata->datetime = hashfileentry(&appxdata->zip, fd, "[Content_Types].xml", dp + 4);
  dp += 4 + hlen;

  /* hash block map */
  memcpy(dp, axbmsig, 4);
  hashfileentry(&appxdata->zip, fd, "AppxBlockMap.xml", dp + 4);
  dp += 4 + hlen;

  /* zero AppxMetadata/CodeIntegrity.cat */
  memcpy(dp, axcisig, 4);
  dp += 4 + hlen;

  x509_init(&appxdata->cb_content);
  offset = x509_appx_contentinfo(&appxdata->cb_content, digest, (int)(dp - digest));
  free(digest);
  return offset;
}

static void
appx_create_signedattrs(struct appxdata *appxdata, int offset, time_t t)
{
  HASH_CONTEXT ctx;

  /* hash the spccontent */
  hash_init(&ctx);
  hash_write(&ctx, appxdata->cb_content.buf + offset, appxdata->cb_content.len - offset);
  hash_final(&ctx);
  x509_init(&appxdata->cb_signedattrs);
  x509_appx_signedattrs(&appxdata->cb_signedattrs, hash_read(&ctx), hash_len(), t);
}

int
appx_read(struct appxdata *appxdata, int fd, char *filename, HASH_CONTEXT *ctx, time_t t)
{
  int offset;

  memset(appxdata, 0, sizeof(*appxdata));
  zip_read(&appxdata->zip, fd);

  if (zip_findentry(&appxdata->zip, "AppxSignature.p7x"))
    return 0;

  /* create spccontentinfo */
  offset = appx_create_contentinfo(appxdata, fd);
  /* create signedattrs */
  appx_create_signedattrs(appxdata, offset, t);
  /* hash signedattrs */
  hash_write(ctx, appxdata->cb_signedattrs.buf, appxdata->cb_signedattrs.len);
  return 1;
}

void
appx_write(struct appxdata *appxdata, int outfd, int fd, struct x509 *cert, int pubalgo, struct x509 *sigcb, struct x509 *othercerts)
{
  static const unsigned char p7xmagic[4] = { 0x50, 0x4b, 0x43, 0x58 };
  struct x509 cb;
  extern int appxdetached;

  x509_init(&cb);
  x509_pkcs7_signed_data(&cb, &appxdata->cb_content, &appxdata->cb_signedattrs, pubalgo, sigcb, cert, othercerts, 0);
  /* prepend file magic */
  x509_insert(&cb, 0, p7xmagic, sizeof(p7xmagic));
  if (appxdetached)
    {
      dowrite(outfd, cb.buf, cb.len);
      x509_free(&cb);
      return;
    }
  /* append file to zip, must use deflated compression */
  zip_appendfile(&appxdata->zip, "AppxSignature.p7x", cb.buf, cb.len, 8, appxdata->datetime);
  zip_write(&appxdata->zip, fd, outfd);
  x509_free(&cb);
}

void
appx_free(struct appxdata *appxdata)
{
  x509_free(&appxdata->cb_content);
  x509_free(&appxdata->cb_signedattrs);
  zip_free(&appxdata->zip);
}

