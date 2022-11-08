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
#include <unistd.h>

#include "inc.h"


#define HEADER_SIGNATURES 62
#define RPMSIGTAG_DSA   267		/* header only sig */
#define RPMSIGTAG_RSA   268		/* header only sig */
#define RPMSIGTAG_SHA1  269		/* header only hash */
#define RPMSIGTAG_LONGSIZE 270
#define RPMSIGTAG_SIZE 1000
#define RPMSIGTAG_PGP  1002
#define RPMSIGTAG_MD5  1004
#define RPMSIGTAG_GPG  1005

/* RPM constants */
static const int  pubtag[]  = { RPMSIGTAG_GPG, RPMSIGTAG_PGP, RPMSIGTAG_GPG };
static const int  pubtagh[] = { RPMSIGTAG_DSA, RPMSIGTAG_RSA, RPMSIGTAG_DSA };	/* header only tags */

static ssize_t
xread(int fd, void *buf, size_t count)
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

static ssize_t
xwrite(int fd, const void *buf, size_t count)
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

int
rpm_insertsig(struct rpmdata *rd, int hdronly, byte *newsig, int newsiglen)
{
  byte *rpmsig = rd->rpmsig;
  int rpmsigsize = rd->rpmsigsize, rpmsigcnt = rd->rpmsigcnt, rpmsigdlen = rd->rpmsigdlen;
  int i, myi, tag, off;
  byte *rsp;
  u32 before;
  int pad;
  byte *region = 0;
  int pubalgo, sigtag;

  if (newsiglen > 1024)
    {
      fprintf(stderr, "signature too big: %d\n", newsiglen);
      return -1;
    }
  pubalgo = pkg2sigpubalgo(newsig, newsiglen);
  if (pubalgo < 0)
    {
      fprintf(stderr, "signature has unknown pubkey algorithm\n");
      return -1;
    }
  sigtag = hdronly ? pubtagh[pubalgo] : pubtag[pubalgo];

  // first some sanity checking
  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      off = getu8c(rsp + 8);
      if (off < 0 || off > rpmsigdlen)
	{
	  fprintf(stderr, "data offset out of range\n");
	  return -1;
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

  rd->rpmsigsize = rpmsigsize;
  rd->rpmsigcnt = rpmsigcnt;
  rd->rpmsigdlen = rpmsigdlen;
  rd->hdrin_md5 = 0;	/* no longer valid */

  /* update sighead with new values */
  rd->rpmsighead[8]  = rpmsigcnt >> 24;
  rd->rpmsighead[9]  = rpmsigcnt >> 16;
  rd->rpmsighead[10] = rpmsigcnt >> 8 ;
  rd->rpmsighead[11] = rpmsigcnt;

  rd->rpmsighead[12] = rpmsigdlen >> 24;
  rd->rpmsighead[13] = rpmsigdlen >> 16;
  rd->rpmsighead[14] = rpmsigdlen >> 8 ;
  rd->rpmsighead[15] = rpmsigdlen;
  return 0;
}

static int
rpm_readsigheader(struct rpmdata *rd, int fd, const char *filename)
{
  byte *p, *rsp;
  int i;
  u32 tag;

  if (read(fd, rd->rpmlead, 96) != 96 || rd->rpmlead[0] != 0xed || rd->rpmlead[1] != 0xab || rd->rpmlead[2] != 0xee || rd->rpmlead[3] != 0xdb)
    {
      fprintf(stderr, "%s: not a rpm\n", filename);
      exit(1);
    }
  if (rd->rpmlead[4] != 0x03 || rd->rpmlead[0x4e] != 0 || rd->rpmlead[0x4f] != 5)
    {
      fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", filename);
      exit(1);
    }
  if (read(fd, rd->rpmsighead, 16) != 16 || rd->rpmsighead[0] != 0x8e || rd->rpmsighead[1] != 0xad || rd->rpmsighead[2] != 0xe8 || rd->rpmsighead[3] != 0x01)
    {
      fprintf(stderr, "%s: bad signature header\n", filename);
      exit(1);
    }
  rd->rpmsigcnt = rd->rpmsighead[8] << 24 | rd->rpmsighead[9] << 16 | rd->rpmsighead[10] << 8 | rd->rpmsighead[11];
  rd->rpmsigdlen = rd->rpmsighead[12] << 24 | rd->rpmsighead[13] << 16 | rd->rpmsighead[14] << 8 | rd->rpmsighead[15];
  rd->rpmsigsize = rd->rpmsigcnt * 16 + ((rd->rpmsigdlen + 7) & ~7);
  rd->rpmsig = malloc(rd->rpmsigsize + 2 * (1024 + 16 + 4));
  if (!rd->rpmsig)
    {
      fprintf(stderr, "%s: no memory for signature area\n", filename);
      exit(1);
    }
  if (xread(fd, rd->rpmsig, rd->rpmsigsize) != rd->rpmsigsize)
    {
      fprintf(stderr, "%s: read error in signature area\n", filename);
      exit(1);
    }
  rd->rpmdataoff = 96 + 16 + rd->rpmsigsize;
  rsp = rd->rpmsig;
  for (i = 0; i < rd->rpmsigcnt; i++)
    {
      tag = rsp[0] << 24 | rsp[1] << 16 | rsp[2] << 8 | rsp[3];
      if (tag == pubtag[PUB_DSA] || tag == pubtag[PUB_RSA] || tag == pubtagh[PUB_DSA] || tag == pubtagh[PUB_RSA])
	{
	  free(rd->rpmsig);
	  rd->rpmsig = 0;
	  return 0;
	}
      if (tag == RPMSIGTAG_SHA1)
	rd->gotsha1 = 1;
      if (tag == RPMSIGTAG_MD5)
	{
	  if (rsp[4] || rsp[5] || rsp[6] || rsp[7] != 7 || rsp[12] || rsp[13] || rsp[14] || rsp[15] != 16)
	    {
	      fprintf(stderr, "%s: bad MD5 tag\n", filename);
	      exit(1);
	    }
	  rd->hdrin_md5 = rd->rpmsig + rd->rpmsigcnt * 16 + (rsp[8] << 24 | rsp[9] << 16 | rsp[10] << 8 | rsp[11]);
	}
      if (tag == RPMSIGTAG_SIZE)
	{
	  if (rsp[4] || rsp[5] || rsp[6] || rsp[7] != 4 || rsp[12] || rsp[13] || rsp[14] || rsp[15] != 1)
	    {
	      fprintf(stderr, "%s: bad SIZE tag\n", filename);
	      exit(1);
	    }
	  p = rd->rpmsig + rd->rpmsigcnt * 16 + (rsp[8] << 24 | rsp[9] << 16 | rsp[10] << 8 | rsp[11]);
	  rd->hdrin_size = (u32)(p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
	}
      rsp += 16;
    }
  return 1;
}

static void
rpm_readheaderpayload(struct rpmdata *rd, int fd, char *filename, HASH_CONTEXT *ctx, HASH_CONTEXT *hctx, int getbuildtime)
{
  byte buf[8192];
  byte btbuf[4];
  MD5_CTX md5ctx;
  u32 lenhdr;
  unsigned long long lensig;
  int l, i;
  int buildtimeoff = 0;

  md5_init(&md5ctx);
  hash_init(hctx);

  lensig = 0;
  lenhdr = 0;
  rd->buildtime = 0;
  while ((l = read(fd, buf, sizeof(buf))) > 0)
    {
      if (!lensig)
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
      hash_write(ctx, buf,  l);
      md5_write(&md5ctx, buf, l);
      if (lenhdr)
	{
	  if (l >= lenhdr)
	    {
	      hash_write(hctx, buf,  lenhdr);
	      lenhdr = 0;
	    }
	  else
	    {
	      hash_write(hctx, buf,  l);
	      lenhdr -= l;
	    }
	}
      lensig += l;
    }
  md5_final(rd->rpmmd5sum, &md5ctx);
  if (lenhdr)
    {
      fprintf(stderr, "%s: bad header size (%u)\n", filename, lenhdr);
      exit(1);
    }
  if (rd->hdrin_size && lensig != rd->hdrin_size)
    {
      fprintf(stderr, "%s: SIZE checksum error %llu %llu\n", filename, rd->hdrin_size, lensig);
      exit(1);
    }
  if (rd->hdrin_md5 && memcmp(rd->hdrin_md5, rd->rpmmd5sum, 16))
    {
      fprintf(stderr, "%s: MD5 checksum error\n", filename);
      exit(1);
    }
  if (getbuildtime)
    {
      if (lensig < buildtimeoff + 4)
	{
	  fprintf(stderr, "cannot calculate buildtime: bad data pointer\n");
	  exit(1);
	}
      rd->buildtime = btbuf[0] << 24 | btbuf[1] << 16 | btbuf[2] << 8 | btbuf[3];
    }
}

int
rpm_read(struct rpmdata *rd, int fd, char *filename, HASH_CONTEXT *ctx, HASH_CONTEXT *hctx, int getbuildtime)
{
  memset(rd, 0, sizeof(*rd));
  if (!rpm_readsigheader(rd, fd, filename))
    return 0;	/* already signed */
  rpm_readheaderpayload(rd, fd, filename, ctx, hctx, getbuildtime);
  return 1;
}

int
rpm_write(struct rpmdata *rd, int foutfd, int fd, int chksumfilefd)
{
  byte buf[8192];
  MD5_CTX md5ctx;
  MD5_CTX chksum_ctx_md5;
  SHA1_CONTEXT chksum_ctx_sha1;
  SHA256_CONTEXT chksum_ctx_sha256;
  int l;
  byte rpmmd5sum2[16];

  if (lseek(fd, rd->rpmdataoff, SEEK_SET) == (off_t)-1)
    {
      perror("lseek");
      return 0;
    }

  xwrite(foutfd, rd->rpmlead, 96);
  xwrite(foutfd, rd->rpmsighead, 16);
  xwrite(foutfd, rd->rpmsig, rd->rpmsigsize);

  if (chksumfilefd >= 0)
    {
      md5_init(&md5ctx);
      md5_write(&md5ctx, rd->rpmlead, 96);
      md5_write(&md5ctx, rd->rpmsighead, 16);
      md5_write(&md5ctx, rd->rpmsig, rd->rpmsigsize);
      md5_final(rd->chksum_leadmd5, &md5ctx);

      md5_init(&chksum_ctx_md5);
      md5_write(&chksum_ctx_md5, rd->rpmlead, 96);
      md5_write(&chksum_ctx_md5, rd->rpmsighead, 16);
      md5_write(&chksum_ctx_md5, rd->rpmsig, rd->rpmsigsize);

      sha1_init(&chksum_ctx_sha1);
      sha1_write(&chksum_ctx_sha1, rd->rpmlead, 96);
      sha1_write(&chksum_ctx_sha1, rd->rpmsighead, 16);
      sha1_write(&chksum_ctx_sha1, rd->rpmsig, rd->rpmsigsize);

      sha256_init(&chksum_ctx_sha256);
      sha256_write(&chksum_ctx_sha256, rd->rpmlead, 96);
      sha256_write(&chksum_ctx_sha256, rd->rpmsighead, 16);
      sha256_write(&chksum_ctx_sha256, rd->rpmsig, rd->rpmsigsize);
    }
  md5_init(&md5ctx);
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
    }
  md5_final(rpmmd5sum2, &md5ctx);
  if (chksumfilefd >= 0)
    {
      md5_final(rd->chksum_md5, &chksum_ctx_md5);
      sha1_final(&chksum_ctx_sha1);
      memcpy(rd->chksum_sha1, sha1_read(&chksum_ctx_sha1), 20);
      sha256_final(&chksum_ctx_sha256);
      memcpy(rd->chksum_sha256, sha256_read(&chksum_ctx_sha256), 32);
    }
  if (memcmp(rpmmd5sum2, rd->rpmmd5sum, 16))
    {
      fprintf(stderr, "rpm has changed, bailing out!\n");
      return 1;
    }
  return 1;
}

void
rpm_free(struct rpmdata *rd)
{
  if (rd->rpmsig)
    free(rd->rpmsig);
  rd->rpmsig = 0;
}

void
rpm_writechecksums(struct rpmdata *rd, int chksumfilefd)
{
  char buf[16*2 + 5+16*2 + 6+20*2 + 8+32*2 + 1], *bp;
  int i;

  if (chksumfilefd < 0)
    return;
  bp = buf;
  for (i = 0; i < 16; i++)
    {
      sprintf(bp, "%02x", rd->chksum_leadmd5[i]);
      bp += 2;
    }
  strcpy(bp, " md5:");
  bp += 5;
  for (i = 0; i < 16; i++)
    {
      sprintf(bp, "%02x", rd->chksum_md5[i]);
      bp += 2;
    }
  strcpy(bp, " sha1:");
  bp += 6;
  for (i = 0; i < 20; i++)
    {
      sprintf(bp, "%02x", rd->chksum_sha1[i]);
      bp += 2;
    }
  strcpy(bp, " sha256:");
  bp += 8;
  for (i = 0; i < 32; i++)
    {
      sprintf(bp, "%02x", rd->chksum_sha256[i]);
      bp += 2;
    }
  *bp++ = '\n';
  if (write(chksumfilefd, buf, bp - buf) != bp - buf)
    {
      perror("chksum write");
      exit(1);
    }
}
