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

#include "inc.h"

static const char bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void
r64enc(char *out, const byte *str, int len)
{
  int a, b, c;

  while (len > 0)
    {
      a = *str++;
      b = --len > 0 ? *str++ : 0;
      c = --len > 0 ? *str++ : 0;
      --len;
      *out++ = bintoasc[a >> 2];
      *out++ = bintoasc[(a & 3) << 4 | b >> 4];
      *out++ = len > -2 ? bintoasc[(b & 15) << 2 | c >> 6] : '=';
      *out++ = len > -1 ? bintoasc[c & 63] : '=';
    }
  *out = 0;
}

char *
r64dec1(char *p, u32 *vp, int *eofp)
{
  int i, x;
  unsigned int v = 0;

  for (i = 0; i < 4; )
    {
      x = *p++;
      if (!x)
        return 0;
      if (x >= 'A' && x <= 'Z')
        x -= 'A';
      else if (x >= 'a' && x <= 'z')
        x -= 'a' - 26;
      else if (x >= '0' && x <= '9')
        x -= '0' - 52;
      else if (x == '+')
        x = 62;
      else if (x == '/')
        x = 63;
      else if (x == '=' || x == '-')
        {
          x = 0;
          if (i == 0)
            {
              *eofp = 3;
              *vp = 0;
              return p - 1;
            }
          *eofp += 1;
        }
      else
        continue;
      v = v << 6 | x;
      i++;
    }
  *vp = v;
  return p;
}

char *
r64dec(char *p, unsigned char **bpp)
{
  u32 v;
  int eof = 0;
  unsigned char *bp = *bpp;
  while (!eof)
    {
      if (!(p = r64dec1(p, &v, &eof)))
        return 0;
      *bp++ = v >> 16;
      *bp++ = v >> 8;
      *bp++ = v;
    }
  *bpp = bp - eof;
  return p;
}

void
printr64(FILE *f, const byte *str, int len)
{
  int i = -1;
  char *p, *s = doalloc(len * 4 / 3 + 5);
  r64enc(s, str, len);
  for (p = s; *p; p++)
    {
      if (++i == 64)
	{
	  i = 0;
	  putc('\n', f);
	}
      putc(*p, f);
    }
  putc('\n', f);
  free(s);
}
