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

static inline int
elf16(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8;
  return buf[0] << 8 | buf[1];
}

static inline u32
elf32(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

static inline u32
elf64(unsigned char *buf, int le, int is64)
{
  if (is64)
    {
      buf += le ? 4 : 0;
      if (buf[0] || buf[1] || buf[2] || buf[3])
        return ~0;
      buf += le ? -4 : 4;
    }
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

int
appimage_read(char *filename, HASH_CONTEXT *ctx)
{
  unsigned char appimagedigest[64]; /*  sha256 sum */
  char *digestfilename;
  FILE *fp;

  digestfilename = doalloc(strlen(filename) + 8);
  sprintf(digestfilename, "%s.digest", filename);
  if ((fp = fopen(digestfilename, "r")) == 0 || 64 != fread(appimagedigest, 1, 64, fp))
    dodie_errno(digestfilename);
  fclose(fp);
  free(digestfilename);
  hash_write(ctx, appimagedigest, 64);
  return 1;
}

void
appimage_write_signature(char *filename, byte *signature, int length)
{
  // find .sha256_sig section offset in ELF file
  unsigned char elfbuf[128];

  int le, is64;
  off_t soff;
  int snum, ssiz;
  int i, l, stridx;
  FILE *fp;
  char *armored_signature;
  size_t siglen;
  off_t sha256_sig_offset = 0;
  u32 sha256_sig_size = 0;
  unsigned char *sects, *strsect;
  u32 slen;

  if ((fp = fopen(filename, "r+")) == 0)
    dodie_errno(filename);
  l = fread(elfbuf, 1, 128, fp);
  if (l < 128)
    dodie("offset 1");
  if (elfbuf[0] != 0x7f || elfbuf[1] != 'E' || elfbuf[2] != 'L' || elfbuf[3] != 'F')
    dodie("not an ELF appimage file");
  is64 = elfbuf[4] == 2;
  le = elfbuf[5] != 2;
  if (is64 && l < 0x40)
    dodie("appimage EOF");
  soff = elf64(is64 ? elfbuf + 40 : elfbuf + 32, le, is64);
  if (soff == (off_t)(u32)~0)
    dodie("bad soff");
  ssiz = elf16(elfbuf + (is64 ? 0x40 - 6 : 0x34 - 6), le);
  if (ssiz < (is64 ? 64 : 40) || ssiz >= 32768)
    dodie("bad ssiz");
  snum = elf16(elfbuf + (is64 ? 0x40 - 4 : 0x34 - 4), le);
  stridx = elf16(elfbuf + (is64 ? 0x40 - 2 : 0x34 - 2), le);
  if (stridx >= snum)
    dodie("bad stridx");
  sects = doalloc(snum * ssiz);
  if (fseek(fp, soff, SEEK_SET) != 0 || fread(sects, 1, snum * ssiz, fp) != snum * ssiz)
    dodie_errno("seek/read sects");
  strsect = sects + stridx * ssiz;
  if (elf32(strsect + 4, le) != 3)
    dodie("bad strsect");
  soff = elf64(is64 ? strsect + 24 : strsect + 16, le, is64);
  slen = elf64(is64 ? strsect + 32 : strsect + 20, le, is64);
  if (soff == (off_t)(u32)~0 || slen > 0xfffffff)
    dodie("bad soff/slen");
  strsect = doalloc(slen);
  if (fseek(fp, soff, SEEK_SET) != 0 || fread(strsect, 1, slen, fp) != slen)
    dodie("seek/read strsect");
  for (i = 0; i < snum; i++)
    {
      u32 o = elf32(sects + i * ssiz, le);
      if (o > slen)
        continue;
      // printf("sect #%d %s (o=%d)\n", i, strsect + o, o);
  
      if (o + 11 <= slen && memcmp(strsect + o, ".sha256_sig", 11) == 0) {
        u32 sh_offset = i * ssiz + (is64 ? 24 : 16);
        sha256_sig_offset = elf64(sects + sh_offset, le, is64);
        sha256_sig_size = elf64(sects + sh_offset + (is64 ? 8 : 4), le, is64);
	if (sha256_sig_offset == (off_t)(u32)~0 || sha256_sig_size > 0xfffffff)
          dodie("bad signature soff/slen");
        break;
      }
    }
  free(strsect);
  free(sects);
  if (sha256_sig_offset == 0)
    dodie(".sha256_sig not found");

  armored_signature = get_armored_signature(signature, length);
  siglen = strlen(armored_signature) + 1;
  if (siglen > sha256_sig_size)
    dodie("section too small for signature");

  if (fseek(fp, sha256_sig_offset, SEEK_SET) == (off_t)-1)
    dodie_errno("fseek");
  if (fwrite(armored_signature, siglen, 1, fp) != 1)
    dodie_errno("signature write");
  for(; siglen < sha256_sig_size; siglen++)
    fputc(0x0, fp);
  if (fclose(fp))
    dodie_errno("fclose error");
  free(armored_signature);
}

