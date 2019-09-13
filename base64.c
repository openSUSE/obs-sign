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

void
printr64(FILE *f, const byte *str, int len)
{
  int a, b, c, i;
  static const byte bintoasc[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  i = -1;
  while (len > 0)
    {
      if (++i == 16)
	{
	  i = 0;
	  putc('\n', f);
	}
      a = *str++;
      b = --len > 0 ? *str++ : 0;
      c = --len > 0 ? *str++ : 0;
      --len;
      putc(bintoasc[a >> 2], f);
      putc(bintoasc[(a & 3) << 4 | b >> 4], f);
      putc(len > -2 ? bintoasc[(b & 15) << 2 | c >> 6] : '=', f);
      putc(len > -1 ? bintoasc[c & 63] : '=', f);
    }
  putc('\n', f);
}

char *
r64dec1(char *p, unsigned int *vp, int *eofp)
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
  unsigned int v;
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

