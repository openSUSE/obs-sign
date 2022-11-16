#include "inc.h"

void *
dorealloc(void *p, size_t sz)
{
  if (sz == 0)
    sz = 1;
  p = p ? realloc(p, sz) : malloc(sz);
  if (!p)
    {
      fprintf(stderr, "out of memory allocating %llu bytes\n", (unsigned long long)sz);
      exit(1);
    }
  return p;
}

void *
doalloc(size_t sz)
{
  return dorealloc(0, sz);
}

void
dodie(const char *msg)
{
  fprintf(stderr, "%s\n", msg);
  exit(1);
}

void
dodie_errno(const char *msg)
{
  perror(msg);
  exit(1);
}

size_t
doread_eof(int fd, unsigned char *buf, size_t len)
{
  size_t ret = 0;
  while (len > 0)
    {
      ssize_t r = read(fd, buf, len > 65536 ? 65536 : len);
      if (r < 0)
	dodie_errno("read");
      if (r == 0)
	break;
      ret += r;
      buf += r;
      len -= r;
    }
  return ret;
}

void
doread(int fd, unsigned char *buf, size_t len)
{
  if (doread_eof(fd, buf, len) != len)
    dodie("unexpeced EOF");
}

void
dowrite(int fd, const unsigned char *buf, size_t len)
{
  while (len > 0)
    {
      ssize_t r = write(fd, buf, len > 65536 ? 65536 : len);
      if (r < 0)
	dodie_errno("write");
      buf += r;
      len -= r;
    }
}

void
doseek(int fd, u64 pos)
{
  if (lseek(fd, (off_t)pos, SEEK_SET) == (off_t)-1)
    dodie_errno("lseek");
}

u64
doseek_eof(int fd, u64 pos)
{
  off_t ret = lseek(fd, -(off_t)pos, SEEK_END);
  if (ret == (off_t)-1)
    dodie_errno("lseek");
  return (u64)ret;
}

void
docopy(int infd, int outfd, u64 len)
{
  unsigned char buf[65536];
  while (len > 0)
    {
      size_t chunk = len > 65536 ? 65536 : len;
      doread(infd, buf, chunk);
      dowrite(outfd, buf, chunk);
      len -= chunk;
    }
}

