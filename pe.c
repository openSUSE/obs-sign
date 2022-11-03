#include "inc.h"

static void
doread(int fd, const char *filename, unsigned char *b, int l)
{
  while (l > 0)
    {
      int r = read(fd, b, l);
      if (r < 0)
	{
	  perror(filename);
	  exit(1);
	}
      if (r == 0)
	{
	  fprintf(stderr, "%s: unexpexted EOF\n", filename);
	  exit(1);
	}
      b += r;
      l -= r;
    }
}

static void
dowrite(int fd, const unsigned char *b, int l)
{
  while (l > 0)
    {
      int r = write(fd, b, l);
      if (r < 0)
        {
	  perror("write");
	  exit(1);
        }
      b += r;
      l -= r;
    }
}

static void
docopy(int outfd, int fd, const char *filename, unsigned int l)
{
  unsigned char buf[4096];
  while (l > 0)
    {
      int chunk = l > sizeof(buf) ? sizeof(buf) : l;
      doread(fd, filename, buf, chunk);
      dowrite(outfd, buf, chunk);
      l -= chunk;
    }
}

static void
update_chksum(unsigned int pos, const unsigned char *b, int l, unsigned int *chkp)
{
  unsigned int c = 0;
  if (!l)
    return;
  if (l > 65536)
    abort();	/* this might overflow */
  if (pos & 1)
    {
      c = *b++ << 8;
      l--;
    }
  for (; l > 1; l -= 2, b += 2)
    c += b[0] + (b[1] << 8);
  if (l)
    c += b[0];
  c += *chkp;
  *chkp = (c & 0xffff) + (c >> 16);
}

static unsigned int
dohash(int fd, char *filename, unsigned int pos, unsigned int l, int toeof, HASH_CONTEXT *ctx, unsigned int *chkp)
{
  unsigned char buf[4096];
  unsigned int hashed = 0;

  if (pos >= 0x40000000)
    {
      fprintf(stderr, "unsupported pe file size\n");
      exit(1);
    }
  if (toeof)
    l = sizeof(buf);
  while (l > 0)
    {
      int r = read(fd, buf, l > sizeof(buf) ? sizeof(buf) : (int)l);
      if (r < 0)
	{
	  perror(filename);
	  exit(1);
	}
      if (r == 0 && toeof)
	break;
      if (r == 0)
	{
	  fprintf(stderr, "%s: unexpexted EOF\n", filename);
	  exit(1);
	}
      if (pos + r >= 0x40000000)
	{
	  fprintf(stderr, "unsupported pe file size\n");
	  exit(1);
	}
      hash_write(ctx, buf, r);
      hashed += r;
      if (chkp)
	update_chksum(pos, buf, r, chkp);
      pos += r;
      if (!toeof)
        l -= r;
    }
  return hashed;
}

static inline
unsigned int getle2(const unsigned char *b)
{
  return b[0] | b[1] << 8;
}

static inline
unsigned int getle4(const unsigned char *b)
{
  return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
}

static inline
void setle4(unsigned char *b, unsigned int v)
{
  b[0] = v & 255;
  b[1] = (v >> 8) & 255;
  b[2] = (v >> 16) & 255;
  b[3] = (v >> 24) & 255;
}

static int
sectioncmp(const void *av, const void *bv)
{
  const unsigned char *a = av;
  const unsigned char *b = bv;
  unsigned int aoff = getle4(a + 20);
  unsigned int boff = getle4(b + 20);
  return aoff < boff ? -1 : aoff > boff ? 1 : 0;
}

int
pe_read(struct pedata *pedata, int fd, char *filename, time_t t)
{
  unsigned char hdr[4096];
  HASH_CONTEXT ctx;
  unsigned int stubsize, opthdrsize;
  unsigned int opthdrmagic;
  unsigned int headersize;
  unsigned int hdd_off;
  unsigned int c_off, c_end;
  unsigned int nsections;
  unsigned int bytes_hashed;
  unsigned int cert_pos = 0;
  int i;
  int offset;

  doread(fd, filename, hdr, 0x40);
  stubsize = getle4(hdr + 0x3c);
  if (stubsize >= sizeof(hdr) - 24 || stubsize < 0x40)
    {
      fprintf(stderr, "illegal stub size: %u\n", stubsize);
      exit(1);
    }
  doread(fd, filename, hdr + 0x40, stubsize - 0x40 + 24);
  if (getle4(hdr + stubsize) != 0x4550)
    {
      fprintf(stderr, "%s: not a PE file\n", filename);
      exit(1);
    }
  opthdrsize = getle2(hdr + stubsize + 4 + 16);
  if (opthdrsize >= sizeof(hdr) || stubsize + 24 + opthdrsize >= sizeof(hdr) || opthdrsize < 64)
    {
      fprintf(stderr, "illegal optional header size: %u\n", opthdrsize);
      exit(1);
    }
  doread(fd, filename, hdr + stubsize + 24, opthdrsize);
  opthdrmagic = getle2(hdr + stubsize + 24);
  if (opthdrmagic != 0x10b && opthdrmagic != 0x20b)
    {
      fprintf(stderr, "unsupported optional header magic: 0x%08x\n", opthdrmagic);
      exit(1);
    }
  hdd_off = opthdrmagic == 0x10b ? 96 : 112;
  if (opthdrsize < hdd_off || ((opthdrsize - hdd_off) & 7) != 0)
    {
      fprintf(stderr, "weird optional header size: %u\n", opthdrsize);
      exit(1);
    }
  headersize = getle4(hdr + stubsize + 24 + 60);
  if (headersize < stubsize + 24 + opthdrsize || headersize > sizeof(hdr))
    {
      fprintf(stderr, "unsupported header size: 0x%08x\n", headersize);
      exit(1);
    }
  doread(fd, filename, hdr + stubsize + 24 + opthdrsize, headersize - (stubsize + 24 + opthdrsize));

  c_off = hdd_off + 8 * 4;
  if (c_off > opthdrsize)
    c_off = opthdrsize;
  c_end = c_off < opthdrsize ? c_off + 8 : c_off;
  if (c_end > c_off && getle4(hdr + stubsize + 24 + c_off + 4) != 0)
    cert_pos = getle4(hdr + stubsize + 24 + c_off);

  if (cert_pos)
    return 0;	/* already signed */

  if (c_end == c_off)
    {
      fprintf(stderr, "missing certificate directory entry\n");
      exit(1);
    }
  pedata->headersize = headersize;
  pedata->c_off = stubsize + 24 + c_off;
  /* clear checksum */
  setle4(hdr + stubsize + 24 + 64, 0);	/* clear checksum */
  pedata->csum = 0;
  pedata->csum_off = stubsize + 24 + 64;
  memcpy(pedata->hdr, hdr, headersize);

  hash_init(&ctx);
  hash_write(&ctx, hdr, stubsize + 24 + 64);
  hash_write(&ctx, hdr + (stubsize + 24 + 68), c_off - 68);
  hash_write(&ctx, hdr + (stubsize + 24 + c_end), headersize - (stubsize + 24 + c_end));
  bytes_hashed = headersize;

  nsections = getle2(hdr + stubsize + 4 + 2);
  if (stubsize + 24 + opthdrsize + nsections * 40 > headersize)
    {
      fprintf(stderr, "section data does not fit into header: 0x%08x\n", nsections);
      exit(1);
    }
  if (nsections > 1)
    qsort(hdr + (stubsize + 24 + opthdrsize), nsections, 40, sectioncmp);
  for (i = 0; i < nsections; i++)
    {
      unsigned char *sp = hdr + (stubsize + 24 + opthdrsize) + 40 * i;
      unsigned int sz = getle4(sp + 16);
      unsigned int off = getle4(sp + 20);
      if (!sz)
	continue;
      if (off != bytes_hashed)
	{
	  fprintf(stderr, "cannot deal with gap between sections: %x %x\n", off, bytes_hashed);
	  exit(1);
	}
      bytes_hashed += dohash(fd, filename, off, sz, 0, &ctx, &pedata->csum);
    }
  if (cert_pos)
    {
      unsigned int sz;
      if (cert_pos < bytes_hashed || (cert_pos & 7) != 0)
	{
	  fprintf(stderr, "illegal cert position: 0x%08x\n", cert_pos);
	  exit(1);
	}
      sz = cert_pos - bytes_hashed;
      bytes_hashed += dohash(fd, filename, bytes_hashed, sz, 0, &ctx, &pedata->csum);
      pedata->filesize = cert_pos;
    }
  else
    {
      bytes_hashed += dohash(fd, filename, bytes_hashed, 0, 1, &ctx, &pedata->csum);
      pedata->filesize = bytes_hashed;
      if ((bytes_hashed & 7) != 0)
	{
	  int pad = 8 - (bytes_hashed & 7);
	  hash_write(&ctx, (const unsigned char *)"\0\0\0\0\0\0\0\0", pad);
	  update_chksum(bytes_hashed, (const unsigned char *)"\0\0\0\0\0\0\0\0", pad, &pedata->csum);
	  bytes_hashed += pad;
	}
    }
  hash_final(&ctx);

  x509_init(&pedata->cb_content);
  offset = x509_pe_contentinfo(&pedata->cb_content, hash_read(&ctx), hash_len());

  /* hash the spccontent */
  hash_init(&ctx);
  hash_write(&ctx, pedata->cb_content.buf + offset, pedata->cb_content.len - offset);
  hash_final(&ctx);

  /* create signedattrs */
  x509_init(&pedata->cb_signedattrs);
  x509_pe_signedattrs(&pedata->cb_signedattrs, hash_read(&ctx), hash_len(), t);
  return 1;
}

void
pe_write(struct pedata *pedata, int outfd, int fd, struct x509 *cert, unsigned char *sig, int siglen, struct x509 *othercerts)
{
  struct x509 cb;
  unsigned int filesizepad;

  x509_init(&cb);
  x509_pkcs7_signed_data(&cb, &pedata->cb_content, &pedata->cb_signedattrs, sig, siglen, cert, othercerts, 0);

  /* add cert header and pad */
  x509_insert(&cb, 0, 0, 8);
  setle4(cb.buf, cb.len);
  setle4(cb.buf + 4, 0x00020200);
  if (cb.len & 7)
    x509_insert(&cb, cb.len, 0, 8 - (cb.len & 7));

  /* now add into certificate directory */
  filesizepad = (8 - (pedata->filesize & 7)) & 7;
  setle4(pedata->hdr + pedata->c_off, pedata->filesize + filesizepad);
  setle4(pedata->hdr + pedata->c_off + 4, cb.len);

  /* update checksum with header and cert data, finalize checksum */
  update_chksum(0, pedata->hdr, pedata->headersize, &pedata->csum);
  update_chksum(pedata->filesize + filesizepad, cb.buf, cb.len, &pedata->csum);
  while (pedata->csum >= 0x10000)
    pedata->csum = (pedata->csum & 0xffff) + (pedata->csum >> 16);
  pedata->csum += pedata->filesize + filesizepad + cb.len;
  setle4(pedata->hdr + pedata->csum_off, pedata->csum);

  /* write signed pe file */
  if (lseek(fd, pedata->headersize, SEEK_SET) != (off_t)pedata->headersize)
    {
      perror("lseek");
      exit(1);
    }
  dowrite(outfd, pedata->hdr, pedata->headersize);
  docopy(outfd, fd, "input file", pedata->filesize - pedata->headersize);
  if (filesizepad)
    dowrite(outfd, (const unsigned char *)"\0\0\0\0\0\0\0\0", filesizepad);
  dowrite(outfd, cb.buf, cb.len);
  x509_free(&cb);
}

void
pe_free(struct pedata *pedata)
{
  x509_free(&pedata->cb_content);
  x509_free(&pedata->cb_signedattrs);
}

