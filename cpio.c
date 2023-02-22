#include "inc.h"

static u32
cpio_hex(byte *p)
{
  u32 x = 0;
  int i;
  for (i = 0; i < 8; i++, p++)
    {
      int c = *p;
      x <<= 4;
      if (c >= '0' && c <= '9')
        x += (c - '0');
      else if (c >= 'a' && c <= 'f')
        x += (c - 'a') + 10;
      else if (c >= 'A' && c <= 'F')
        x += (c - 'A') + 10;
      else
        dodie("invalid cpio data");
    }
  return x;
}

static void
cpio_tohex(byte *p, u32 x)
{
  static const char hexstr[] = "0123456789abcdef";
  int i;
  p += 7;
  for (i = 0; i < 8; i++, p--)
    {
      int c = (x & 15);
      x >>= 4;
      *p = (byte)hexstr[c];
    }
}

byte *
cpio_read(int fd, int *typep, int reserve)
{
  byte hdr[110];	/* cpio header */
  byte *cpio;
  u32 mode, size, namesize, namepad;

  doread(fd, hdr, 110);
  if (memcmp(hdr, "070701", 6))
    dodie("bad/unsupported cpio file");
  mode = cpio_hex(hdr + 14);
  size = cpio_hex(hdr + 54);
  namesize = cpio_hex(hdr + 94);
  if (namesize > 8192)
    dodie("illegal name size");
  if (size > 0x40000000)
    dodie("illegal file size");
  namepad = (6 - (namesize & 3)) & 3;
  cpio = doalloc(110 + namesize + namepad + 1 + (reserve ? reserve + 4 : 0));
  memcpy(cpio, hdr, 110);
  doread(fd, cpio + 110, namesize + namepad);
  cpio[110 + namesize] = 0;
  if (!size && !strcmp((char *)cpio + 110, "TRAILER!!!"))
    *typep = CPIO_TYPE_TRAILER;
  else if (((mode >> 12) & 15) == 8)
    *typep = CPIO_TYPE_FILE;
  else
    *typep = CPIO_TYPE_OTHER;
  return cpio;
}

u32
cpio_name_append(byte *cpio, char *suf)
{
  u32 namepad, namesize = strlen((char *)cpio + 110);
  strcpy((char *)cpio + 110 + namesize, suf);
  namesize += strlen(suf) + 1;
  namepad = (6 - (namesize & 3)) & 3;
  memset(cpio + 110 + namesize, 0, namepad);
  cpio_tohex(cpio + 94, namesize);
  return namepad;
}

u32
cpio_size_set(byte *cpio, u32 size)
{
  cpio_tohex(cpio + 54, size);
  return (4 - (size & 3)) & 3;
}

u32
cpio_size_get(byte *cpio, u32 *padp)
{
  u32 size = cpio_hex(cpio + 54);
  if (padp)
    *padp = ((4 - (size & 3)) & 3);
  return size;
}

u32
cpio_headnamesize(byte *cpio)
{
  u32 namesize = cpio_hex(cpio + 94);
  return 110 + namesize + ((6 - (namesize & 3)) & 3);
}

