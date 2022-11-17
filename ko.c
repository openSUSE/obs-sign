#include "inc.h"
#include "bele.h"

int ko_read(int fd, char *filename, HASH_CONTEXT *ctx)
{
  u64 length;
  byte buf[8192];

  doread(fd, buf, 4);
  if (buf[0] != 0x7f || buf[1] != 0x45 || buf[2] != 0x4c || buf[3] != 0x46)
    {
      fprintf(stderr, "%s: not an ELF binary\n", filename);
      exit(1);
    }
  length = doseek_eof(fd, 28) + 28;
  doread(fd, buf, 28);
  if (!memcmp(buf, "~Module signature appended~\n", 28))
    return 0;
  doseek(fd, 0);
  while (length > 0)
    {
      int chunk = length > sizeof(buf) ? sizeof(buf) : (int)length;
      doread(fd, buf, chunk);
      hash_write(ctx, buf, chunk);
      length -= chunk;
    }
  return 1;
}

void
ko_write(int outfd, int fd, struct x509 *cb)
{
  u64 length;

  x509_insert(cb, cb->len, 0, 40);
  setbe4(cb->buf + cb->len - 40, 0x00000200);
  setbe4(cb->buf + cb->len - 32, cb->len - 40);
  memcpy(cb->buf + cb->len - 28, "~Module signature appended~\n", 28);
  length = doseek_eof(fd, 0);
  doseek(fd, 0);
  docopy(fd, outfd, length);
  dowrite(outfd, cb->buf, cb->len);
}
