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

int
clearsign(int fd, char *filename, char *outfilename, HASH_CONTEXT *ctx, const char *hname, int isfilter, int force, FILE **foutp)
{
  byte *cbuf;
  int l, cbufl;
  int have = 0;
  int i, j;
  int nl = 0;
  int first = 1;
  FILE *fout;

  if ((cbuf = malloc(8192)) == NULL)
    {
      fprintf(stderr, "no mem for clearsign buffer\n");
      exit(1);
    }
  cbufl = 8192;
  l = read(fd, cbuf, cbufl);
  if (l < 0)
    {
      perror("read");
      exit(1);
    }
  if (l >= 34 && !strncmp((char *)cbuf, "-----BEGIN PGP SIGNED MESSAGE-----", 34))
    return 0;	/* already signed */
  for (i = 0; i < l; i++)
    {
      if (cbuf[i] >= 32 || cbuf[i] == '\t' || cbuf[i] == '\r' || cbuf[i] == '\n')
	continue;
      first++;
    }
  if (first > 4 && !force)
    {
      fprintf(stderr, "%s: won't clearsign binaries\n", filename);
      exit(1);
    }
  opensocket();
  if (isfilter)
    fout = stdout;
  else if ((fout = fopen(outfilename, "w")) == 0)
    {
      perror(outfilename);
      exit(1);
    }
  fprintf(fout, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: %s\n\n", hname);
  while (first || (l = read(fd, cbuf + have, cbufl - have)) > 0 || (l == 0 && have))
    {
      first = 0;
      if (nl)
	hash_write(ctx, (const unsigned char *)"\r\n",  2);
      nl = 0;
      l += have;
      for (i = 0; i < l; i++)
	if (cbuf[i] == '\n')
	  break;
      if (i == l && i == cbufl && l != have)
	{
	  cbufl *= 2;
	  cbuf = realloc(cbuf, cbufl);
	  if (!cbuf)
	    {
	      fprintf(stderr, "no mem for clearsign buffer\n");
	      exit(1);
	    }
	  have = l;
	  continue;
	}
      if ((l > 0 && cbuf[0] == '-') || (l > 4 && !strncmp((char *)cbuf, "From ", 5)))
	fprintf(fout, "- ");
      if (i == l)
	{
	  /* EOF reached, line is unterminated */
	  cbuf[l] = '\n';
	  l++;
	}
      if (i > 20000)
	{
	  fprintf(stderr, "line too long for clearsign\n");
	  exit(1);
	}
      fwrite(cbuf, 1, i + 1, fout);
      for (j = i - 1; j >= 0; j--)
	if (cbuf[j] != '\r' && cbuf[j] != ' ' && cbuf[j] != '\t')
	  break;
      if (j >= 0)
	hash_write(ctx, cbuf, j + 1);
      nl = 1;
      i++;
      if (i < l)
	memmove(cbuf, cbuf + i, l - i);
      have = l - i;
    }
  if (l < 0)
    {
      perror("read");
      if (!isfilter)
	unlink(outfilename);
      exit(1);
    }
  free(cbuf);
  *foutp = fout;
  return 1;
}
