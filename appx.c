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

#include <unistd.h>

#include "inc.h"

extern int appxsig2stdout;

static const unsigned char axmgsig[4] = { 0x41, 0x50, 0x50, 0x58 };
static const unsigned char axpcsig[4] = { 0x41, 0x58, 0x50, 0x43 };
static const unsigned char axcdsig[4] = { 0x41, 0x58, 0x43, 0x44 };
static const unsigned char axctsig[4] = { 0x41, 0x58, 0x43, 0x54 };
static const unsigned char axbmsig[4] = { 0x41, 0x58, 0x42, 0x4d };
static const unsigned char axcisig[4] = { 0x41, 0x58, 0x43, 0x49 };

static void
dosha256hash(int fd, unsigned long long size, unsigned char *out)
{
  unsigned char buf[65536];
  HASH_CONTEXT ctx;

  hash_init(&ctx);
  while (size > 0)
    {
      int r = read(fd, buf, size > 65536 ? 65536 : size);
      if (r < 0)
	{
	  perror("read");
	  exit(1);
	}
      if (r == 0)
	{
	  fprintf(stderr, "dosha256hash: unexpeced EOF\n");
	  exit(1);
	}
      hash_write(&ctx, buf, r);
      size -= r;
    }
  hash_final(&ctx);
  memcpy(out, hash_read(&ctx), 32);
}

static unsigned int
hashfileentry(struct zip *zip, int fd, char *fn, unsigned char *dig)
{
  unsigned char *entry;
  unsigned long long datasize;

  entry = zip_findentry(zip, fn);
  if (!entry)
    {
      fprintf(stderr, "missing '%s' file", fn);
      exit(1);
    }
  datasize = zip_seekdata(zip, fd, entry);
  dosha256hash(fd, datasize, dig);
  return zip_entry_datetime(entry);
}

int
appx_read(struct appxdata *appxdata, int fd, char *filename, time_t t)
{
  unsigned char digest[4 + (4 + 32) * 5];
  int offset;
  HASH_CONTEXT ctx;

  if (hashalgo != HASH_SHA256)
    {
      fprintf(stderr, "can only use sha256 for hashing\n");
      exit(1);
    }
  memset(appxdata, 0, sizeof(*appxdata));
  zip_read(&appxdata->zip, fd);

  if (zip_findentry(&appxdata->zip, "AppxSignature.p7x"))
    return 0;

  /* create digests */
  memset(digest, 0, sizeof(digest));
  memcpy(digest, axmgsig, 4);
  memcpy(digest + 4, axpcsig, 4);
  /* hash from start to central dir */
  if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
    {
      perror("seek");
      exit(1);
    }
  dosha256hash(fd, appxdata->zip.cd_offset, digest + 8);
  /* hash from central dir to end */
  memcpy(digest + 40, axcdsig, 4);
  dosha256hash(fd, appxdata->zip.size - appxdata->zip.cd_offset, digest + 44);
  /* hash content types */
  memcpy(digest + 76, axctsig, 4);
  appxdata->datetime = hashfileentry(&appxdata->zip, fd, "[Content_Types].xml", digest + 80);
  /* hash block map */
  memcpy(digest + 112, axbmsig, 4);
  hashfileentry(&appxdata->zip, fd, "AppxBlockMap.xml", digest + 116);
  /* zero AppxMetadata/CodeIntegrity.cat */
  memcpy(digest + 148, axcisig, 4);

  /* create spccontentinfo */
  x509_init(&appxdata->cb_content);
  offset = x509_appx_contentinfo(&appxdata->cb_content, digest, sizeof(digest));

  /* hash the spccontent */
  hash_init(&ctx);
  hash_write(&ctx, appxdata->cb_content.buf + offset, appxdata->cb_content.len - offset);
  hash_final(&ctx);

  /* create signedattrs */
  x509_init(&appxdata->cb_signedattrs);
  x509_appx_signedattrs(&appxdata->cb_signedattrs, hash_read(&ctx), hash_len(), t);
  return 1;
}

void
appx_write(struct appxdata *appxdata, int outfd, int fd, struct x509 *cert, unsigned char *sig, int siglen, struct x509 *othercerts)
{
  static const unsigned char p7xmagic[4] = { 0x50, 0x4b, 0x43, 0x58 };
  struct x509 cb;

  x509_init(&cb);
  x509_pkcs7_signed_data(&cb, &appxdata->cb_content, &appxdata->cb_signedattrs, sig, siglen, cert, othercerts, 0);
  /* add file magic */
  x509_insert(&cb, 0, p7xmagic, sizeof(p7xmagic));
  if (appxsig2stdout)
    {
      write(1, cb.buf, cb.len);
      exit(0);
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

