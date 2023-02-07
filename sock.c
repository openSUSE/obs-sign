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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>

#include "inc.h"


static int sock = -1;

extern char *test_sign;
extern char *host;
extern int port;
extern uid_t uid;
extern int use_unprivileged_ports;

void
opensocket(void)
{
  static int hostknown;
  static struct sockaddr_in svt;
  int optval;

  if (test_sign)
    return;
  if (!hostknown)
    {
      svt.sin_addr.s_addr = inet_addr(host);
      svt.sin_family = AF_INET;
      if (svt.sin_addr.s_addr == -1)
	{
	  struct hostent *hp;
	  if (!(hp = gethostbyname(host)))
	    {
	      printf("%s: unknown host\n", host);
	      exit(1);
	    }
	  memmove(&svt.sin_addr, hp->h_addr, hp->h_length);
	  svt.sin_family = hp->h_addrtype;
	}
      svt.sin_port = htons(port);
      hostknown = 1;
    }
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    dodie_errno("socket");
  if (!use_unprivileged_ports)
    {
      if (uid)
	{
	  if (seteuid(0))
	    dodie_errno("seteuid");
	}
      while (bindresvport(sock, NULL) != 0)
	{
	  if (errno != EADDRINUSE)
	    dodie_errno("bindresvport");
	  sleep(1);
	}
      if (uid)
	{
	  if (seteuid(uid))
	    dodie_errno("seteuid");
	}
    }
  if (connect(sock, (struct sockaddr *)&svt, sizeof(svt)))
    dodie_errno(host);
  optval = 1;
  setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
}

void
closesocket()
{
  if (sock != -1)
    {
      close(sock);
      sock = -1;
    }
}

static pid_t
pipe_and_fork(int *pip)
{
  pid_t pid;
  if (pipe(pip) == -1)
    dodie_errno("pipe");
  if ((pid = fork()) == (pid_t)-1)
    dodie_errno("fork");
  if (pid == 0)
    {
      close(pip[0]);
      dup2(pip[1], 1);
      close(pip[1]);
    }
  else
    close(pip[1]);
  return pid;
}

static void
doreq_test(byte *buf, int inbufl, int bufl)
{
  pid_t pid;
  int pip[2];
  
  pid = pipe_and_fork(pip);
  if (pid == 0)
    {
      pid = pipe_and_fork(pip);
      if (pid == 0)
	{
	  while (inbufl > 0)
	    {
	      int l = write(1, buf, inbufl);
	      if (l == -1)
		{
		  perror("write");
		  _exit(1);
		}
	      buf += l;
	      inbufl -= l;
	    }
	  _exit(0);
	}
      dup2(pip[0], 0);
      close(pip[0]);
      execlp(test_sign, test_sign, "--test-sign", (char *)0);
      perror(test_sign);
      _exit(1);
    }
  sock = pip[0];
}

static void
reap_test_signd()
{
  int status;
  pid_t pid = waitpid(0, &status, 0);
  if (pid <= 0)
    dodie_errno("waitpid");
  if (status)
    {
      fprintf(stderr, "test signd returned status 0x%x\n", status);
      exit(1);
    }
}

int
doreq_raw(byte *buf, int inbufl, int bufl)
{
  int l, outl, errl;

  if (sock == -1)
    opensocket();		/* better late then never */
  if (test_sign)
    doreq_test(buf, inbufl, bufl);
  else if (write(sock, buf, inbufl) != inbufl)
    {
      perror("write");
      closesocket();
      return -1;
    }

  l = 0; 
  for (;;) 
    {
      int ll;
      if (l == bufl)
	{
	  fprintf(stderr, "packet too big\n");
	  closesocket();
	  return -1;
	}
      ll = read(sock, buf + l, bufl - l);
      if (ll == -1)
	{
	  perror("read");
	  closesocket();
	  return -1;
	}
      if (ll == 0)
	break;
      l += ll;
    }
  closesocket();
  if (test_sign)
    reap_test_signd();
  if (l < 6)
    {
      fprintf(stderr, "packet too small\n");
      return -1;
    }
  outl = buf[2] << 8 | buf[3];
  errl = buf[4] << 8 | buf[5];
  if (l != outl + errl + 6)
    {
      fprintf(stderr, "packet size mismatch %d %d %d\n", l, outl, errl);
      return -1;
    }
  if (errl)
    fwrite(buf + 6 + outl, 1, errl, stderr);
  if (buf[0] << 8 | buf[1])
    return -(buf[0] << 8 | buf[1]);
  memmove(buf, buf + 6, outl);
  return outl;
}

int
doreq_old(const char *user, const char *digest, const char *digestalgo, byte *buf, int bufl)
{
  size_t userlen = strlen(user);
  size_t digestlen = strlen(digest);
  size_t digestalgolen = digestalgo ? strlen(digestalgo) + 1 : 0;
  if (4 + userlen + digestlen + digestalgolen > bufl)
    {
      fprintf(stderr, "request buffer overflow\n");
      closesocket();
      return -1;
    }
  buf[0] = userlen >> 8;
  buf[1] = userlen & 255;
  buf[2] = (digestlen + digestalgolen) >> 8;
  buf[3] = (digestlen + digestalgolen) & 255;
  memcpy(buf + 4, user, userlen);
  if (digestalgolen)
    {
      memcpy(buf + 4 + userlen, digestalgo, digestalgolen - 1);
      buf[4 + userlen + digestalgolen - 1] = ':';
    }
  memcpy(buf + 4 + userlen + digestalgolen, digest, digestlen);
  return doreq_raw(buf, 4 + userlen + digestalgolen + digestlen, bufl);
}

int
doreq(int argc, const char **argv, byte *buf, int bufl, int nret)
{
  byte *bp;
  int i, l, v, outl;

  bp = buf + 2;
  *bp++ = 0;
  *bp++ = 0;
  *bp++ = argc >> 8;
  *bp++ = argc & 255;
  for (i = 0; i < argc; i++)
    {
      v = strlen(argv[i]);
      *bp++ = v >> 8;
      *bp++ = v & 255;
    }
  for (i = 0; i < argc; i++)
    {
      v = strlen(argv[i]);
      if (bp + v > buf + bufl)
	{
	  fprintf(stderr, "request buffer overflow\n");
	  closesocket();
	  return -1;
	}
      memcpy(bp, argv[i], v);
      bp += v;
    }
  v = bp - (buf + 4);
  buf[0] = v >> 8;
  buf[1] = v & 255;

  outl = doreq_raw(buf, (int)(bp - buf), bufl);
  if (outl < 0)
    return outl;

  if (nret)
    {
      /* verify returned data */
      if (outl < 2 + 2 * nret)
	{
	  fprintf(stderr, "answer too small\n");
	  return -1;
	}
      if (buf[0] != 0 || buf[1] != nret)
	{
	  fprintf(stderr, "bad return count\n");
	  return -1;
	}
      l = 2;
      for (i = 0; i < nret; i++)
	l += 2 + (buf[2 + i * 2] << 8 | buf[2 + i * 2 + 1]);
      if (l != outl)
	{
	  fprintf(stderr, "answer size mismatch\n");
	  return -1;
	}
    }
  return outl;
}

/* do a request with one or two results */
int
doreq_12(int argc, const char **argv, byte *buf, int bufl, int *outl2p)
{
  int outl = doreq(argc, argv, buf, bufl, outl2p ? 2 : 1);
  if (outl >= 0)
    {
      outl = buf[2] << 8 | buf[3];
      if (outl2p)
	{
	  int outl2 = buf[4] << 8 | buf[5];
	  memmove(buf, buf + 6, outl + outl2);
	  *outl2p = outl2;
	}
      else
        memmove(buf, buf + 4, outl);
    }
  return outl;
}

