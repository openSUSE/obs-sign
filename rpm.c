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
#include "bele.h"


#define HEADER_SIGNATURES 62
#define RPMSIGTAG_DSA   267		/* header only sig */
#define RPMSIGTAG_RSA   268		/* header only sig */
#define RPMSIGTAG_SHA1  269		/* header only hash */
#define RPMSIGTAG_LONGSIZE 270
#define RPMSIGTAG_SIZE 1000
#define RPMSIGTAG_PGP  1002
#define RPMSIGTAG_MD5  1004
#define RPMSIGTAG_GPG  1005
#define RPMSIGTAG_RESERVEDSPACE	1008

/* RPM constants */
static const int  pubtag[]  = { RPMSIGTAG_GPG, RPMSIGTAG_PGP, RPMSIGTAG_GPG, RPMSIGTAG_GPG };
static const int  pubtagh[] = { RPMSIGTAG_DSA, RPMSIGTAG_RSA, RPMSIGTAG_DSA, RPMSIGTAG_DSA };	/* header only tags */

static inline u32
getbe4c(const unsigned char *p)
{
  if (p[0])
    dodie("header data overflow");
  return getbe4(p);
}

static byte *
rpm_sanitycheck(struct rpmdata *rd)
{
  byte *rpmsig = rd->rpmsig;
  int rpmsigcnt = rd->rpmsigcnt;
  u32 rpmsigdlen = rd->rpmsigdlen;
  byte *rsp, *region = 0;
  u32 off;
  int i, tag;

  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      tag = getbe4c(rsp);
      off = getbe4c(rsp + 8);
      if (off > (region ? rpmsigdlen - 16 : rpmsigdlen))
	dodie("data offset out of range");
      if (tag >= 61 && tag < 64)
	{
	  if (i != 0)
	    dodie("region must be first entry");
	  region = rsp;
	  if (getbe4(region + 4) != 7 || getbe4(region + 12) != 16)
	    dodie("region must have type 7 and size 16");
	  if (rpmsigdlen < 16)
	    dodie("datalen too small for region");
	  if (off + 16 != rpmsigdlen)
	    dodie("region must include the complete signature header");
	}
    }
  if (region)
    {
      rsp = rpmsig + rpmsigcnt * 16 + getbe4c(region + 8);
      if (getbe4(rsp + 8) != (u32)(-(rpmsigcnt * 16)))
	dodie("region data does not match entry count");
    }
  return region;
}

static u32
datalen_strarr(byte *rpmsig, int rpmsigcnt, u32 rpmsigdlen, u32 off, u32 cnt)
{
  byte *bpstart = rpmsig + rpmsigcnt * 16 + off;
  byte *bpmax = rpmsig + rpmsigcnt * 16 + rpmsigdlen;
  byte *bp = bpstart;
  while (cnt-- > 0)
    {
      while (*bp++)
	;
      if (bp > bpmax)
	dodie("datalen overflow");
    }
  return (u32)(bp - bpstart);
}

static u32
datalen(byte *rpmsig, int rpmsigcnt, u32 rpmsigdlen, byte *rsp)
{
  int type = getbe4c(rsp + 4), cnt = getbe4c(rsp + 12);

  if (type == 6 || type == 8 || type == 9)
    return datalen_strarr(rpmsig, rpmsigcnt, rpmsigdlen, getbe4c(rsp + 8), type == 6 ? 1 : cnt);
  if (type == 3)
    return 2 * cnt;
  else if (type == 4)
    return 4 * cnt;
  else if (type == 5)
    return 8 * cnt;
  return cnt;
}

static inline u32
dataalign(int type)
{
  if (type == 3)
    return 2;
  else if (type == 4)
    return 4;
  else if (type == 5)
    return 8;
  return 1;
}

static int
realign_cmp(const void *a, const void *b)
{
  const byte *rspa = *(const byte **)a, *rspb = *(const byte **)b;
  u32 offa = getbe4c(rspa + 8), offb = getbe4c(rspb + 8);
  if (offa != offb)
    return offa < offb ? -1 : 1;
  if (rspa != rspb)
    return rspa < rspb ? -1 : 1;
  return 0;
}

static void
rpm_realign(struct rpmdata *rd, byte *region)
{
  byte *rpmsig = rd->rpmsig;
  int rpmsigcnt = rd->rpmsigcnt;
  u32 rpmsigdlen = rd->rpmsigdlen;
  u32 maxrpmsigdlen = rpmsigdlen + 16;
  byte *rsp, **rsps;
  u32 off, lastoff, dl, align;
  int i, j;

  /* order entries by offset, put region last */
  rsps = doalloc(rpmsigcnt * sizeof(byte *));
  for (i = 0, rsp = rpmsig + (region ? 16 : 0); i < rpmsigcnt; i++, rsp += 16)
    rsps[i] = rsp;
  if (region)
    rsps[rpmsigcnt - 1] = rpmsig;
  if (rpmsigcnt > (region ? 2 : 1))
    qsort(rsps, rpmsigcnt - (region ? 1 : 0), sizeof(byte *), realign_cmp);

  lastoff = 0;
  for (i = 0; i < rpmsigcnt; i++)
    {
      rsp = rsps[i];
      align = dataalign((int)getbe4c(rsp + 4));
      off = getbe4c(rsp + 8);
      if (lastoff > off)
	{
	  fprintf(stderr, "lastoff overlaps with data: %d %d\n", lastoff, off);
	  exit(1);
	}
      if (align > 1 && (lastoff % align) != 0)
	lastoff += align - (lastoff % align);
      if (lastoff != off)
	{
	  /* alignment mismatch, move over from off to lastoff */
	  if (lastoff > off && rpmsigdlen + (lastoff - off) > maxrpmsigdlen)
	    dodie("rpm_realign alignment space overflow");
	  memmove(rpmsig + rpmsigcnt * 16 + lastoff, rpmsig + rpmsigcnt * 16 + off, rpmsigdlen - off);
	  if (lastoff > off)
	    memset(rpmsig + rpmsigcnt * 16 + off, 0, lastoff - off);
	  rpmsigdlen += lastoff - off;
	  /* update all offsets */
	  for (j = i; j < rpmsigcnt; j++)
	    setbe4(rsps[j] + 8, getbe4c(rsps[j] + 8) + lastoff - off);
	  off += lastoff - off;
	}
      dl = datalen(rpmsig, rpmsigcnt, rpmsigdlen, rsp);
      if (dl > 0xffffff)
	dodie("datalen overflow");
      lastoff = off + dl;
    }
  if (lastoff > rpmsigdlen)
    {
      fprintf(stderr, "lastoff overlaps with data: %d %d\n", lastoff, rpmsigdlen);
      exit(1);
    }
  rd->rpmsigdlen = rpmsigdlen;
  free(rsps);
}

static void
rpm_adaptreserved(struct rpmdata *rd, byte *region, int diff)
{
  byte *rpmsig = rd->rpmsig;
  int rpmsigcnt = rd->rpmsigcnt;
  byte *rpmsigdata = rpmsig + 16 * rpmsigcnt;
  int o, l;
  byte *rsp;
  
  if (!rpmsigcnt || !diff)
    return;
  /* the reserved space must be the last tag and must be the last
   * entry in the data segment */
  rsp = rpmsig + 16 * (rpmsigcnt - 1);
  if (getbe4c(rsp) != RPMSIGTAG_RESERVEDSPACE || getbe4(rsp + 4) != 7)
    return;
  o = getbe4c(rsp + 8);
  l = getbe4c(rsp + 12);
  if (o + l != rd->rpmsigdlen - (region ? 16 : 0))
    return;	/* reserved space is not at end of data */
  if (diff < 0 && l + diff < 1)
    return;	/* not enough space left */
  if (region)
    {
      /* check region offset again just in case... */
      if (getbe4c(region + 8) != o + l)
        dodie("rpm_adaptreserved: unexpected region offset");
      memmove(rpmsigdata + o + l + diff, rpmsigdata + o + l, 16);
      setbe4(region + 8, o + l + diff);
    }
  if (diff > 0)
    memset(rpmsigdata + o + l, 0, diff);
  else
    memset(rpmsigdata + rd->rpmsigdlen + diff, 0, -diff);
  l += diff;
  setbe4(rsp + 12, l);
  rd->rpmsigdlen += diff;
}

int
rpm_insertsig(struct rpmdata *rd, int hdronly, byte *newsig, int newsiglen)
{
  byte *rpmsig = rd->rpmsig;
  int rpmsigcnt = rd->rpmsigcnt;
  u32 rpmsigsize = rd->rpmsigsize, rpmsigdlen = rd->rpmsigdlen;
  u32 oldsigspace = rpmsigcnt * 16 + rpmsigdlen, newsigspace;
  u32 off, before;
  int i, myi, tag;
  byte *rsp, *region;
  int pad;
  int pubalgo, sigtag;

  if (newsiglen < 0 || newsiglen > 1024)
    {
      fprintf(stderr, "new signature size is bad: %d\n", newsiglen);
      return -1;
    }
  pubalgo = pkg2sigpubalgo(newsig, newsiglen);
  if (pubalgo < 0)
    {
      fprintf(stderr, "signature has unknown pubkey algorithm\n");
      return -1;
    }
  sigtag = hdronly ? pubtagh[pubalgo] : pubtag[pubalgo];

  /* first do some sanity checking */
  region = rpm_sanitycheck(rd);

  /* now find the correct place to insert the signature */
  for (i = 0, tag = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      tag = getbe4c(rsp);
      if (tag == sigtag)
	abort();	/* must not insert already existing tag */
      if (tag > sigtag)
	break;
    }
  /* fprintf(stderr, "inserting at position %d of %d\n", i, rpmsigcnt); */

  /* insert it */
  memmove(rsp + 16, rsp, rpmsigsize - i * 16);
  memset(rsp, 0, 16);
  setbe4(rsp, sigtag);
  setbe4(rsp + 4, 7);
  setbe4(rsp + 12, newsiglen);

  if (i < rpmsigcnt)
    before = getbe4c(rsp + 16 + 8);
  else if (region)
    before = getbe4c(region + 8);
  else
    before = rpmsigdlen;
  if (before > rpmsigdlen)
    abort();

  /* fprintf(stderr, "before=%d sigdlen=%d\n", before, rpmsigdlen); */
  rpmsigcnt++;
  if (before < rpmsigdlen)
    memmove(rpmsig + rpmsigcnt * 16 + before + newsiglen, rpmsig + rpmsigcnt * 16 + before, rpmsigdlen - before);
  memmove(rpmsig + rpmsigcnt * 16 + before, newsig, newsiglen);
  setbe4(rsp + 8, before);
  rpmsigdlen += newsiglen;

  /* now fix up all entries behind us */
  myi = i;
  for (i = 0, rsp = rpmsig; i < rpmsigcnt; i++, rsp += 16)
    {
      if (i == myi)
	continue;
      off = getbe4c(rsp + 8);
      if (off >= before)
        setbe4(rsp + 8, off + newsiglen);
    }

  /* update entry count in region data */
  if (region)
    {
      off = getbe4c(region + 8);
      rsp = rpmsig + rpmsigcnt * 16 + off;
      setbe4(rsp + 8, getbe4(rsp + 8) - 16);
    }
  rd->rpmsigcnt = rpmsigcnt;
  rd->rpmsigdlen = rpmsigdlen;

  /* correct the alignment of all entries */
  rpm_realign(rd, region);
  rpmsigdlen = rd->rpmsigdlen;

  /* if the last entry is the reserved tag, shrink it */
  newsigspace = rpmsigcnt * 16 + rpmsigdlen;
  if (newsigspace > oldsigspace)
    {
      rpm_adaptreserved(rd, region, oldsigspace - newsigspace);
      rpmsigdlen = rd->rpmsigdlen;
    }

  /* pad to multiple of 8 */
  pad = 7 - ((rpmsigdlen + 7) & 7);
  if (pad)
    memset(rpmsig + rpmsigcnt * 16 + rpmsigdlen, 0, pad);
  rpmsigsize = rpmsigcnt * 16 + rpmsigdlen + pad;
  rd->rpmsigsize = rpmsigsize;
  rd->hdrin_md5 = 0;	/* no longer valid */

  /* update sighead with new values */
  setbe4(rd->rpmsighead + 8, rpmsigcnt);
  setbe4(rd->rpmsighead + 12, rpmsigdlen);
  return 0;
}

static int
rpm_readsigheader(struct rpmdata *rd, int fd, const char *filename)
{
  byte *p, *rsp;
  int i;
  u32 tag;

  doread(fd, rd->rpmlead, 96);
  if (getbe4(rd->rpmlead) != 0xedabeedb)
    {
      fprintf(stderr, "%s: not a rpm\n", filename);
      exit(1);
    }
  if (rd->rpmlead[4] != 0x03 || rd->rpmlead[0x4e] != 0 || rd->rpmlead[0x4f] != 5)
    {
      fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", filename);
      exit(1);
    }
  doread(fd, rd->rpmsighead, 16);
  if (getbe4(rd->rpmsighead) != 0x8eade801)
    {
      fprintf(stderr, "%s: bad signature header\n", filename);
      exit(1);
    }
  rd->rpmsigcnt = getbe4c(rd->rpmsighead + 8);
  rd->rpmsigdlen = getbe4c(rd->rpmsighead + 12);
  if (rd->rpmsigcnt > 0xffff || rd->rpmsigdlen > 0xfffffff)
    dodie("signature header overflow");
  rd->rpmsigsize = rd->rpmsigcnt * 16 + ((rd->rpmsigdlen + 7) & ~7);
  rd->rpmsig = doalloc(rd->rpmsigsize + 2 * (1024 + 16 + 16) + 8);	/* 16(entry) + 16(alignment) */
  doread(fd, rd->rpmsig, rd->rpmsigsize);
  memset(rd->rpmsig + rd->rpmsigsize, 0, 2 * (1024 + 16 + 16) + 8);	/* zero out extra space */
  rd->rpmdataoff = 96 + 16 + rd->rpmsigsize;
  for (i = 0, rsp = rd->rpmsig; i < rd->rpmsigcnt; i++, rsp += 16)
    {
      tag = getbe4c(rsp);
      if (tag == pubtag[PUB_DSA] || tag == pubtag[PUB_RSA] || tag == pubtagh[PUB_DSA] || tag == pubtagh[PUB_RSA])
	{
	  /* already signed */
	  free(rd->rpmsig);
	  rd->rpmsig = 0;
	  return 0;
	}
      if (tag == RPMSIGTAG_SHA1)
	rd->gotsha1 = 1;
      if (tag == RPMSIGTAG_MD5)
	{
          int o = getbe4c(rsp + 8);
	  if (getbe4(rsp + 4) != 7 || getbe4(rsp + 12) != 16 || o + 16 > rd->rpmsigdlen)
	    {
	      fprintf(stderr, "%s: bad MD5 tag\n", filename);
	      exit(1);
	    }
	  rd->hdrin_md5 = rd->rpmsig + rd->rpmsigcnt * 16 + o;
	}
      if (tag == RPMSIGTAG_SIZE)
	{
          int o = getbe4c(rsp + 8);
	  if (getbe4(rsp + 4) != 4 || getbe4(rsp + 12) != 1 || o + 4 > rd->rpmsigdlen)
	    {
	      fprintf(stderr, "%s: bad SIZE tag\n", filename);
	      exit(1);
	    }
	  p = rd->rpmsig + rd->rpmsigcnt * 16 + o;
	  rd->hdrin_size = (u32)(p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
	}
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
  u64 lensig;
  int l, i;
  u32 buildtimeoff = 0;

  md5_init(&md5ctx);
  hash_init(hctx);

  lensig = 0;
  lenhdr = 0;
  rd->buildtime = 0;
  for (;;)
    {
      l = read(fd, buf, sizeof(buf));
      if (l < 0)
	dodie_errno("read");
      if (l == 0)
	break;
      if (!lensig)
	{
	  if (l < 16)
	    dodie("cannot calculate header size: short read");
	  if (buf[8] || buf[9] || buf[12] > 0x0f)
	    dodie("header size overflow");
	  lenhdr = 16 + 16 * getbe4(buf + 8) + getbe4(buf + 12);
	}
      if (getbuildtime && !lensig)
	{
	  int n = getbe4(buf + 8);
	  if ((l - 16) / 16 < n)
	    n = (l - 16) / 16;
	  for (i = 0; i < n; i++)
	    if (!memcmp(buf + 16 + 16 * i, "\0\0\003\356\0\0\0\4", 8))
	      break;
	  if (i == n)
	    dodie("cannot calculate buildtime: tag not found");
	  buildtimeoff = getbe4(buf + 16 + 16 * i + 8);
	  if (buildtimeoff > 0x0fffffff)
	    dodie("illegal buildtime offset");
	  buildtimeoff += 16 + 16 * getbe4c(buf + 8);
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
	dodie("cannot calculate buildtime: bad data pointer");
      rd->buildtime = getbe4(btbuf);
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

void
rpm_write(struct rpmdata *rd, int foutfd, int fd, int chksumfilefd)
{
  byte buf[8192];
  MD5_CTX md5ctx;
  MD5_CTX chksum_ctx_md5;
  SHA1_CONTEXT chksum_ctx_sha1;
  SHA256_CONTEXT chksum_ctx_sha256;
  int l;
  byte rpmmd5sum2[16];

  doseek(fd, rd->rpmdataoff);

  dowrite(foutfd, rd->rpmlead, 96);
  dowrite(foutfd, rd->rpmsighead, 16);
  dowrite(foutfd, rd->rpmsig, rd->rpmsigsize);

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
  for (;;)
    {
      l = read(fd, buf, sizeof(buf));
      if (l < 0)
	dodie_errno("read");
      if (l == 0)
	break;
      md5_write(&md5ctx, buf, l);
      dowrite(foutfd, buf, l);
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
    dodie("rpm has changed, bailing out!");
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
  dowrite(chksumfilefd, (unsigned char *)buf, bp - buf);
}
