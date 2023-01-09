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
#include "bele.h"

/* 64bit le support */

static u64
getle8(unsigned char *p)
{
  return (u64)getle4(p) | ((u64)getle4(p + 4)) << 32;
}

static void
setle8(unsigned char *p, u64 x)
{
  setle4(p, x);
  setle4(p + 4, x >> 32);
}

/* main */

void
zip_read(struct zip *zip, int fd)
{
  unsigned char eocd[22];
  unsigned char eocd64l[20];
  u64 eocd64_offset;
  u64 size;
  u64 left;
  unsigned char *p;
  int fnlen;

  memset(zip, 0, sizeof(*zip));
  size = doseek_eof(fd, 20 + 22);
  if (size >= 0x100000000000ULL)
    dodie("zip archive too big");
  size += 20 + 22;
  zip->size = size;
  doread(fd, eocd64l, 20);
  doread(fd, eocd, 22);
  if (getle4(eocd) != 0x06054b50 || getle2(eocd + 20) != 0)
    dodie("not a (commentless) zip archive");
  if (getle2(eocd + 4) || getle2(eocd + 6))
    dodie("multidisc zip archive");
  if (getle2(eocd + 8) != 0xffff || getle2(eocd + 10) != 0xffff || getle4(eocd + 12) != 0xffffffff || getle4(eocd + 16) != 0xffffffff)
    dodie("no zip64 end of central directory record");
  if (getle4(eocd64l) != 0x07064b50)
    dodie("missing zip64 locator");
  if (getle4(eocd64l + 4) != 0)
    dodie("multidisc zip archive?");
  eocd64_offset = getle8(eocd64l + 8);
  if (eocd64_offset >= size - (20 + 22) || size - (20 + 22) - eocd64_offset >= 0x10000 || size - (20 + 22) - eocd64_offset < 56)
    dodie("invalid eocd64 offset");
  doseek(fd, eocd64_offset);
  zip->eocd_size = size - (20 + 22) - eocd64_offset;
  zip->eocd = doalloc(zip->eocd_size);
  doread(fd, zip->eocd, zip->eocd_size);
  if (getle4(zip->eocd) != 0x06064b50)
    dodie("missing zip64 end of central directory record");
  if (getle4(zip->eocd + 16) != 0 || getle4(zip->eocd + 20) != 0)
    dodie("multidisc zip archive??");
  zip->cd_offset = getle8(zip->eocd + 48);
  if (zip->cd_offset > eocd64_offset)
    dodie("invalid cd offset");
  zip->cd_size = eocd64_offset - zip->cd_offset;
  if (zip->cd_size != getle8(zip->eocd + 40))
    dodie("central directory size mismatch");
  if (zip->cd_size >= 0x1000000)
    dodie("central directory too big");
  doseek(fd, zip->cd_offset);
  zip->cd = doalloc(zip->cd_size);
  doread(fd, zip->cd, zip->cd_size);
  /* scan through directory entries */
  p = zip->cd;
  left = zip->cd_size;
  while (left > 0)
    {
      if (left < 46 || getle4(p) != 0x02014b50)
	dodie("bad directory entry");
      fnlen = getle2(p + 28);
      if (fnlen == 0 || left < 46 + fnlen)
	dodie("bad directory entry");
      fnlen += getle2(p + 30) + getle2(p + 32) + 46;
      if (left < fnlen)
        dodie("bad directory entry");
      p += fnlen;
      left -= fnlen;
      zip->num++;
    }
  if (getle8(zip->eocd + 24) != zip->num || getle8(zip->eocd + 32) != zip->num)
    dodie("central directory entries mismatch");
}

unsigned char *
zip_iterentry(struct zip *zip, unsigned char **iter)
{
  unsigned char *p = *iter;
  if (p == zip->cd + zip->cd_size)
    return 0;
  *iter = p + 46 + getle2(p + 28) + getle2(p + 30) + getle2(p + 32);
  return p;
}

char *
zip_entry_name(unsigned char *entry, int *lenp)
{
  *lenp = getle2(entry + 28);
  return (char *)(entry + 46);
}

u32
zip_entry_datetime(unsigned char *entry)
{
  return getle4(entry + 12);
}

unsigned char *
zip_findentry(struct zip *zip, char *fn)
{
  unsigned char *iter = zip->cd;
  unsigned char *entry;
  int fnl = strlen(fn);
  while ((entry = zip_iterentry(zip, &iter)) != 0)
    {   
      int entnamel;
      char *entname = zip_entry_name(entry, &entnamel);
      if (entnamel == fnl && memcmp(entname, fn, fnl) == 0)
        return entry;
    }   
  return 0;
}

u64
zip_entry_fhpos(unsigned char *entry)
{
  u32 pos = getle4(entry + 42);
  if (pos == 0xffffffff)
    dodie("zip64 not supported yet");
  return pos;
}

u64
zip_seekdata(struct zip *zip, int fd, unsigned char *entry)
{
  u64 pos = zip_entry_fhpos(entry);
  unsigned char lfh[30];
  u32 size;

  if (pos >= zip->cd_offset - zip->appendedsize)
    dodie("zip_seekdata: illegal file header position");
  doseek(fd, pos);
  doread(fd, lfh, 30);
  if (getle4(lfh) != 0x04034b50)
    dodie("zip_seekdata: not a file header at that position");
  if (getle2(lfh + 8) != 0)
    dodie("only uncompressed files supported");
  size = getle4(lfh + 18);
  if (size == 0xffffffff)
    dodie("zip64 not supported yet");
  pos += 30 + getle2(lfh + 26) + getle2(lfh + 28);
  if (pos + size > zip->cd_offset - zip->appendedsize)
    dodie("data overlaps central directory");
  doseek(fd, pos);
  return size;
}

void
zip_free(struct zip *zip)
{
  if (zip->cd)
    free(zip->cd);
  if (zip->eocd)
    free(zip->eocd);
  if (zip->appended)
    free(zip->appended);
}

static unsigned char *
dummydeflate(unsigned char *in, int inlen, int *outlenp)
{
  unsigned char *out, *p;
  if (inlen > 100000)
    dodie("dummydeflate: file too big");
  out = p = doalloc(inlen + ((inlen + 65535) / 65535) * 5);
  while (inlen > 0)
    {
      int chunk = inlen > 65535 ? 65535 : inlen;
      inlen -= chunk;
      p[0] = inlen ? 0 : 1;
      p[1] = chunk & 255;
      p[2] = chunk / 256;
      p[3] = ~p[1];
      p[4] = ~p[2];
      p += 5;
      memcpy(p, in, chunk);
      p += chunk;
    }
  *outlenp = p - out;
  return out;
}

static u32 crc32_tab[] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static u32
crc32buf(unsigned char *buf, u64 len)
{
  u32 x = 0xffffffff;
  for (; len > 0; len--)
    x = crc32_tab[(x ^ *buf++) & 0xff] ^ (x >> 8);
  return x ^ 0xffffffff;
}

void
zip_appendfile(struct zip *zip, char *fn, unsigned char *file, u64 filelen, int comp, u32 datetime)
{
  unsigned char *compfile = file;
  u64 compfilelen = filelen;
  unsigned char *lfh, *entry;
  u64 size;
  u32 crc32;
  int fnl = strlen(fn);
  if (fnl > 0xfffe)
    dodie("zip_appendfile: file name too long");
  if (comp != 0 && comp != 8)
    dodie("zip_appendfile: unsupported compression");
  if (filelen > 0xfffffffe || zip->cd_offset > 0xfffffffe)
    dodie("zip_appendfile: zip64 not supported");
  crc32 = crc32buf(file, filelen);
  if (comp == 8)
    {
      int deflatelen;
      compfile = dummydeflate(file, (int)filelen, &deflatelen);
      compfilelen = deflatelen;
    }
  size = 30 + fnl + compfilelen;
  zip->appended = dorealloc(zip->appended, zip->appendedsize + size);
  lfh = zip->appended + zip->appendedsize;
  zip->cd = dorealloc(zip->cd, zip->cd_size + 46 + fnl);
  entry = zip->cd + zip->cd_size;
  zip->cd_size += 46 + fnl;
  zip->appendedsize += size;
  zip->cd_offset += size;
  zip->size += size + 46 + fnl;
  zip->num++;

  setle4(lfh, 0x04034b50);
  memcpy(lfh + 30, fn, fnl);
  memcpy(lfh + 30 + fnl, compfile, compfilelen);
  setle2(lfh + 4, 20);
  setle2(lfh + 6, 0);
  setle2(lfh + 8, comp);
  setle4(lfh + 10, datetime);
  setle4(lfh + 14, crc32);
  setle4(lfh + 18, compfilelen);
  setle4(lfh + 22, filelen);
  setle2(lfh + 26, fnl);
  setle2(lfh + 28, 0);

  setle4(entry, 0x02014b50);
  memcpy(entry + 46, fn, fnl);
  setle2(entry + 4, 45);
  setle2(entry + 6, 20);
  setle2(entry + 8, 0);
  setle2(entry + 10, comp);
  setle4(entry + 12, datetime);
  setle4(entry + 16, crc32);
  setle4(entry + 20, compfilelen);
  setle4(entry + 24, filelen);
  setle2(entry + 28, fnl);
  setle2(entry + 30, 0);
  setle2(entry + 32, 0);
  setle2(entry + 34, 0);	/* disk no */
  setle2(entry + 36, 0);
  setle4(entry + 38, 0);
  setle4(entry + 42, zip->cd_offset - size);
  
  /* patch eocd entries */
  setle8(zip->eocd + 24, zip->num);
  setle8(zip->eocd + 32, zip->num);
  setle8(zip->eocd + 40, zip->cd_size);
  setle8(zip->eocd + 48, zip->cd_offset);

  if (file != compfile)
    free(compfile);
}

void
zip_write(struct zip *zip, int zipfd, int fd)
{
  unsigned char eocdl[20];
  unsigned char eocdr[22];

  setle4(eocdl, 0x07064b50);
  setle4(eocdl + 4, 0);
  setle8(eocdl + 8, zip->cd_offset + zip->cd_size);
  setle4(eocdl + 16, 1);

  setle4(eocdr, 0x06054b50);
  setle2(eocdr + 4, 0);
  setle2(eocdr + 6, 0);
  setle2(eocdr + 8, 0xffff);
  setle2(eocdr + 10, 0xffff);
  setle4(eocdr + 12, 0xffffffff);
  setle4(eocdr + 16, 0xffffffff);
  setle2(eocdr + 20, 0);

  /* copy old */
  doseek(zipfd, 0);
  docopy(zipfd, fd, zip->cd_offset - zip->appendedsize);
  dowrite(fd, zip->appended, zip->appendedsize);
  dowrite(fd, zip->cd, zip->cd_size);	/* central dir */
  dowrite(fd, zip->eocd, zip->eocd_size);	/* end of central dir */
  dowrite(fd, eocdl, 20);
  dowrite(fd, eocdr, 22);
}

