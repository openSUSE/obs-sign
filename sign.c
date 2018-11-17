/*
 * Copyright (c) 2006-2013 Michael Schroeder, Novell Inc.
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

#define MYPORT 5167

static char *host;
static char *user;
static char *algouser;
static int port = MYPORT;
static int allowuser;
static char *test_sign;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pwd.h>

#include "inc.h"

static uid_t uid;

static int opensocket(void)
{
  static int hostknown;
  static struct sockaddr_in svt;
  int sock;
  int optval;

  if (test_sign)
    return -1;
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
    {
      perror("socket");
      exit(1);
    }
  if (uid)
    seteuid(0);
  for (;;)
    {
      if (!bindresvport(sock, NULL))
	break;
      if (errno != EADDRINUSE)
	{
	  perror("bindresvport");
	  exit(1);
	}
      sleep(1);
    }
  if (uid)
    {
      if (seteuid(uid))
	{
	  perror("seteuid");
	  exit(1);
	}
    }
  if (connect(sock, (struct sockaddr *)&svt, sizeof(svt)))
    {
      perror(host);
      exit(1);
    }
  optval = 1;
  setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
  return sock;
}

static int verbose;

static const char *const hashname[] = {"SHA1", "SHA256"};
static const int  hashlen[] = {20, 32};

int hashalgo = HASH_SHA1;
static const char *timearg;
static char *privkey;
static int privkey_read;
static int noheaderonly;
static int pkcs1pss;
static char *chksumfile;
static int chksumfilefd = -1;
static int dov4sig;
static int pubalgoprobe = -1;

#define MODE_UNSET        0
#define MODE_RPMSIGN      1
#define MODE_CLEARSIGN    2
#define MODE_DETACHEDSIGN 3
#define MODE_KEYID        4
#define MODE_PUBKEY       5
#define MODE_KEYGEN       6
#define MODE_KEYEXTEND    7
#define MODE_RAWDETACHEDSIGN 8
#define MODE_RAWOPENSSLSIGN 9
#define MODE_CREATECERT   10
#define MODE_APPIMAGESIGN 11

static const char *const modes[] = {
  "?", "rpm sign", "clear sign", "detached sign", "keyid", "pubkey", "keygen", "keyextend",
  "raw detached sign" "raw openssl sign" "cert create", "appimage sign"
};

static void
readprivkey(void)
{
  FILE *fp;
  int l, ll;
  if (privkey_read)
    return;
  if ((fp = fopen(privkey, "r")) == 0)
    {
      perror(privkey);
      exit(1);
    }
  privkey_read = 1;
  privkey = malloc(8192);
  *privkey = 0;
  l = 0;
  while (l < 8192 && (ll = fread(privkey + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 0)
    {
      fprintf(stderr, "empty private\n");
      exit(1);
    }
  if (l == 8192)
    {
      fprintf(stderr, "private key too large\n");
      exit(1);
    }
  if (privkey[l - 1] == '\n')
    l--;
  privkey[l] = 0;
}

static pid_t
pipe_and_fork(int *pip)
{
  pid_t pid;
  if (pipe(pip) == -1)
    {
      perror("pipe");
      exit(1);
    }
  if ((pid = fork()) == (pid_t)-1)
    {
      perror("fork");
      exit(1);
    }
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

static int
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
  return pip[0];
}

static void
reap_test_signd()
{
  int status;
  pid_t pid = waitpid(0, &status, 0);
  if (pid <= 0)
    {
      perror("waitpid");
      exit(1);
    }
  if (status)
    {
      fprintf(stderr, "test signd returned status 0x%x\n", status);
      exit(1);
    }
}

static int
doreq_old(int sock, byte *buf, int inbufl, int bufl)
{
  int l, outl, errl;

  if (test_sign)
    sock = doreq_test(buf, inbufl, bufl);
  else if (write(sock, buf, inbufl) != inbufl)
    {
      perror("write");
      close(sock);
      return -1;
    }

  l = 0; 
  for (;;) 
    {
      int ll;
      if (l == bufl)
	{
	  fprintf(stderr, "packet too big\n");
	  close(sock);
	  return -1;
	}
      ll = read(sock, buf + l, bufl - l);
      if (ll == -1)
	{
	  perror("read");
	  close(sock);
	  return -1;
	}
      if (ll == 0)
	break;
      l += ll;
    }
  close(sock);
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

static int
doreq(int sock, int argc, const char **argv, byte *buf, int bufl, int nret)
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
	  close(sock);
	  return -1;
	}
      memcpy(bp, argv[i], v);
      bp += v;
    }
  v = bp - (buf + 4);
  buf[0] = v >> 8;
  buf[1] = v & 255;

  outl = doreq_old(sock, buf, (int)(bp - buf), bufl);
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

static inline int
elf16(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8;
  return buf[0] << 8 | buf[1];
}

static inline unsigned int
elf32(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

static inline unsigned int
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

static int
probe_pubalgo()
{
  char hashhex[1024];
  byte buf[8192], *bp;
  u32 signtime = time(NULL);
  int i, sock, ulen, outl;

  sock = opensocket();
  ulen = strlen(user);
  bp = (byte *)hashhex;
  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
    sprintf((char *)bp, "01");
  sprintf((char *)bp, "@00%08x", (unsigned int)signtime);

  if (!privkey)
    {
      /* old style sign */
      if (ulen + strlen(hashhex) + 4 + 1 + (hashalgo == HASH_SHA1 ? 0 : strlen(hashname[hashalgo]) + 1) > sizeof(buf))
	{
	  close(sock);
	  return -1;
	}
      buf[0] = ulen >> 8;
      buf[1] = ulen;
      buf[2] = 0;
      buf[3] = 0;
      memmove(buf + 4, user, ulen);
      bp = buf + 4 + ulen;
      if (hashalgo != HASH_SHA1)
	{
	  strcpy((char *)bp, hashname[hashalgo]);
	  bp += strlen((const char *)bp);
	  *bp++ = ':';
	}
      strcpy((char *)bp, hashhex);
      bp += strlen((char *)bp);
      buf[3] = bp - (buf + 4 + ulen);
      outl = doreq_old(sock, buf, (int)(bp - buf), sizeof(buf));
    }
  else
    {
      const char *args[5];

      readprivkey();
      args[0] = "privsign";
      args[1] = algouser;
      args[2] = privkey;
      args[3] = hashhex;
      outl = doreq(sock, 4, args, buf, sizeof(buf), 1);
      if (outl >= 0)
	{
	  outl = buf[2] << 8 | buf[3];
	  memmove(buf, buf + 4, outl);
	}
    }
  return outl > 0 ? findsigpubalgo(buf, outl) : -1;
}

static int
sign(char *filename, int isfilter, int mode)
{
  u32 signtime;
  struct rpmdata rpmrd;
  byte buf[8192], *bp;
  byte *cbuf;
  int cbufl;
  int l, fd;
  int i;
  byte hash[5], *p, *ph = 0;
  HASH_CONTEXT ctx;
  HASH_CONTEXT hctx;
  int force = 1;
  int outl, outlh;
  int sock;
  int ulen;
  char *outfilename = 0;
  FILE *fout = 0;
  int foutfd = -1;
  int getbuildtime = 0;

  unsigned char *v4sigtrail = 0;
  int v4sigtraillen = 0;

  if (mode == MODE_UNSET)
    {
      force = 0;
      if (isfilter)
        {
	  fprintf(stderr, "please specify a mode for filter usage (see sign --help).\n");
	  exit(1);
        }
      l = strlen(filename);
      if (l > 4 && (!strcmp(filename + l - 4, ".rpm") || !strcmp(filename + l - 4, ".spm")))
	mode = MODE_RPMSIGN;
      else if (l > 9 && (!strcmp(filename + l - 9, ".AppImage"))) {
        mode = MODE_APPIMAGESIGN;
      } else
        mode = MODE_CLEARSIGN;
    }
  if (mode == MODE_APPIMAGESIGN && isfilter)
    {
      fprintf(stderr, "appimage sign cannot work as filter.\n");
      exit(1);
    }
  if (isfilter)
    fd = 0;
  else if ((fd = open(filename, O_RDONLY)) == -1)
    {
      perror(filename);
      exit(1);
    }
  else if (mode != MODE_APPIMAGESIGN)
    {
      outfilename = malloc(strlen(filename) + 16);
      if (!outfilename)
	{
	  fprintf(stderr, "out of memory for filename\n");
	  exit(1);
	}
      if (mode == MODE_DETACHEDSIGN)
	sprintf(outfilename, "%s.asc", filename);
      else if (mode == MODE_RAWDETACHEDSIGN || mode == MODE_RAWOPENSSLSIGN)
	sprintf(outfilename, "%s.sig", filename);
      else
	sprintf(outfilename, "%s.sIgN%d", filename, getpid());
    }
  if (!timearg || mode == MODE_KEYID || mode == MODE_PUBKEY)
    signtime = time(NULL);
  else if (*timearg >= '0' && *timearg <= '9')
    signtime = strtoul(timearg, NULL, 0);
  else if (mode == MODE_RPMSIGN && !strcmp(timearg, "buildtime"))
    {
      getbuildtime = 1;
      signtime = 0;		/* rpmsign && buildtime */
    }
  else
    {
      struct stat stb;
      if (fstat(fd, &stb))
	{
	  perror("fstat");
	  exit(1);
	}
      if (S_ISFIFO(stb.st_mode))
	{
	  fprintf(stderr, "cannot use mtime on pipes\n");
	  exit(1);
	}
      signtime = stb.st_mtime;
    }

  if (mode == MODE_RPMSIGN)
    {
      memset(&rpmrd, 0, sizeof(rpmrd));
      if (!rpm_readsigheader(&rpmrd, fd, filename))
	{
	  fprintf(isfilter ? stderr : stdout, "%s: already signed\n", filename);
	  close(fd);
	  if (outfilename)
	    free(outfilename);
	  if (isfilter)
	    exit(1);
	  return 1;
	}
    }

  hash_init(&ctx);
  if (mode == MODE_CLEARSIGN)
    {
      int have = 0;
      int i, j;
      int nl = 0;
      int first = 1;

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
	{
	  fprintf(isfilter ? stderr : stdout, "%s: already signed\n", filename);
	  close(fd);
	  if (outfilename)
	    free(outfilename);
	  if (isfilter)
	    exit(1);
	  return(1);
	}
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
      sock = opensocket();
      if (isfilter)
	fout = stdout;
      else if ((fout = fopen(outfilename, "w")) == 0)
	{
	  perror(outfilename);
	  exit(1);
	}
      foutfd = fileno(fout);
      fprintf(fout, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: %s\n\n", hashname[hashalgo]);
      while (first || (l = read(fd, cbuf + have, cbufl - have)) > 0 || (l == 0 && have))
	{
	  first = 0;
	  if (nl)
	    hash_write(&ctx, (const unsigned char *)"\r\n",  2);
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
	    hash_write(&ctx, cbuf, j + 1);
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
      cbuf = 0;
      cbufl = 0;
    }
  else if (mode == MODE_KEYID || mode == MODE_PUBKEY)
    {
      /* sign empty string */
      sock = opensocket();
    }
  else if (mode == MODE_APPIMAGESIGN)
    {
      unsigned char appimagedigest[64]; /*  sha256 sum */
      char *digestfilename;
      FILE *fp;

      sock = opensocket();
      digestfilename = malloc(strlen(filename) + 8);
      sprintf(digestfilename, "%s.digest", filename);
      if ((fp = fopen(digestfilename, "r")) == 0 || 64 != fread(appimagedigest, 1, 64, fp))
        {
          perror(digestfilename);
          exit(1);
        }
      fclose(fp);
      free(digestfilename);
      hash_write(&ctx, appimagedigest, 64);
    }
  else if (mode == MODE_RPMSIGN)
    {
      sock = opensocket();
      if (!rpm_readheaderpayload(&rpmrd, fd, filename, &ctx, &hctx, getbuildtime))
	exit(1);
      if (getbuildtime)
	signtime = rpmrd.buildtime;
    }
  else
    {
      sock = opensocket();
      while ((l = read(fd, buf, sizeof(buf))) > 0)
	hash_write(&ctx, buf,  l);
    }

  if (verbose && mode != MODE_KEYID && mode != MODE_PUBKEY)
    {
      if (*user)
        fprintf(isfilter ? stderr : stdout, "%s %s user %s\n", modes[mode],  filename, user);
      else
        fprintf(isfilter ? stderr : stdout, "%s %s\n", modes[mode],  filename);
    }
  if (mode != MODE_RAWOPENSSLSIGN && mode != MODE_KEYID && mode != MODE_PUBKEY && dov4sig)
    v4sigtrail = genv4sigtrail(mode == MODE_CLEARSIGN ? 1 : 0, pubalgoprobe >= 0 ? pubalgoprobe : PUB_RSA, hashalgo, signtime, &v4sigtraillen);
  if (mode == MODE_RAWOPENSSLSIGN)
    {
      hash[0] = pkcs1pss ? 0xbc : 0x00;
      hash[1] = hash[2] = hash[3] = hash[4] = 0;
    }
  else
    {
      hash[0] = mode == MODE_CLEARSIGN ? 0x01 : 0x00; /* class */
      hash[1] = signtime >> 24;
      hash[2] = signtime >> 16;
      hash[3] = signtime >> 8;
      hash[4] = signtime;
      if (v4sigtrail)
        hash_write(&ctx, v4sigtrail, v4sigtraillen);
      else
        hash_write(&ctx, hash, 5);
    }
  hash_final(&ctx);
  p = hash_read(&ctx);
  ph = 0;
  outlh = 0;
  if (mode == MODE_RPMSIGN)
    {
      if (v4sigtrail)
        hash_write(&hctx, v4sigtrail, v4sigtraillen);
      else
        hash_write(&hctx, hash, 5);
      hash_final(&hctx);
      /* header only seems to work only if there's a header only hash */
      if (!noheaderonly && rpmrd.gotsha1)
        ph = hash_read(&hctx);
    }

  ulen = strlen(user);
  if (!privkey && !ph)
    {
      /* old style sign */
      if (ulen + hashlen[hashalgo] * 2 + 1 + 5 * 2 + 4 + 1 + (hashalgo == HASH_SHA1 ? 0 : strlen(hashname[hashalgo]) + 1) > sizeof(buf))
	{
	  fprintf(stderr, "packet too big\n");
	  if (mode == MODE_CLEARSIGN && !isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      buf[0] = ulen >> 8;
      buf[1] = ulen;
      buf[2] = 0;
      buf[3] = 0;
      memmove(buf + 4, user, ulen);
      bp = buf + 4 + ulen;
      if (hashalgo != HASH_SHA1)
	{
	  strcpy((char *)bp, hashname[hashalgo]);
	  bp += strlen((const char *)bp);
	  *bp++ = ':';
	}
      if (mode == MODE_PUBKEY)
	{
	  strcpy((char *)bp, "PUBKEY");
	  bp += 6;
	}
      else
	{
	  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	    sprintf((char *)bp, "%02x", p[i]);
	  *bp++ = '@';
	  for (i = 0; i < 5; i++, bp += 2)
	    sprintf((char *)bp, "%02x", hash[i]);
	}
      buf[3] = bp - (buf + 4 + ulen);
      outl = doreq_old(sock, buf, (int)(bp - buf), sizeof(buf));
      if (outl >= 0)
        memmove(buf + 6, buf, outl);	/* make 1st arg start at offset 6, we know there is room */
    }
  else
    {
      /* new style sign with doreq */
      const char *args[5];
      char *bp;
      char hashhex[1024];
      char hashhexh[1024];
      int argc;

      if (mode == MODE_PUBKEY)
	{
	  fprintf(stderr, "pubkey mode does not work with a private key\n");
	  exit(1);
	}
      if (privkey)
        readprivkey();
      bp = hashhex;
      for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	sprintf(bp, "%02x", p[i]);
      *bp++ = '@';
      for (i = 0; i < 5; i++, bp += 2)
	sprintf(bp, "%02x", hash[i]);
      *bp = 0;
      if (ph)
	{
	  bp = hashhexh;
	  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
	    sprintf(bp, "%02x", ph[i]);
	  *bp++ = '@';
	  for (i = 0; i < 5; i++, bp += 2)
	    sprintf(bp, "%02x", hash[i]);
	  *bp = 0;
	}
      args[0] = privkey ? "privsign" : "sign";
      args[1] = algouser;
      argc = 2;
      if (privkey)
        args[argc++] = privkey;
      args[argc++] = hashhex;
      if (ph)
        args[argc++] = hashhexh;
      outl = doreq(sock, argc, args, buf, sizeof(buf), ph ? 2 : 1);
      if (outl >= 0)
	{
	  outl = buf[2] << 8 | buf[3];
	  outlh = ph ? (buf[4] << 8 | buf[5]) : 0;
	  if (outl == 0 || (ph && outlh == 0))
	    {
	      if (mode == MODE_CLEARSIGN && !isfilter)
		unlink(outfilename);
	      fprintf(stderr, "server returned empty signature\n");
	      exit(1);
	    }
	  if (!ph)
	    memmove(buf + 6, buf + 4, outl);	/* make 1st arg always start at offset 6, we know there is room */
	}
    }
  if (outl < 0)
    {
      if (mode == MODE_CLEARSIGN && !isfilter)
	unlink(outfilename);
      exit(-outl);
    }
  if (mode == MODE_KEYID)
    {
      int sigl;
      byte *sig = pkg2sig(buf + 6, outl, &sigl);
      byte *issuer = findsigissuer(sig, sigl);
      if (!issuer)
	{
	  fprintf(stderr, "issuer not found in signature\n");
	  exit(1);
	}
      printf("%02X%02X%02X%02X\n", issuer[4], issuer[5], issuer[6], issuer[7]);
      exit(0);
    }

  /* transcode v3sigs to v4sigs if requested */
  if (v4sigtrail)
    {
      outl = v3tov4(v4sigtrail, buf + 6, outl, outlh, sizeof(buf) - 6 - outl - outlh);
      if (ph)
        outlh = v3tov4(v4sigtrail, buf + 6 + outl, outlh, 0, sizeof(buf) - 6 - outl - outlh);
      free(v4sigtrail);
    }

  if (isfilter)
    {
      fout = stdout;
      foutfd = 1;
    }
  else if (mode != MODE_CLEARSIGN && mode != MODE_APPIMAGESIGN)
    {
      if ((fout = fopen(outfilename, "w")) == 0)
	{
	  perror(outfilename);
	  exit(1);
	}
      foutfd = fileno(fout);
    }

  if (mode == MODE_CLEARSIGN || mode == MODE_DETACHEDSIGN)
    {
      write_armored_signature(fout, buf + 6, outl);
    }
  else if (mode == MODE_RAWDETACHEDSIGN)
    {
      if (fwrite(buf + 6, outl, 1, fout) != 1)
	{
	  perror("fwrite");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
    }
  else if (mode == MODE_RAWOPENSSLSIGN)
    {
      int rawssllen = 0;
      int sigl;
      byte *sig = pkg2sig(buf + 6, outl, &sigl);
      byte *rawssl = getrawopensslsig(sig, sigl, &rawssllen);
      if (!rawssl)
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (fwrite(rawssl, rawssllen, 1, fout) != 1)
	{
	  perror("fwrite");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      free(rawssl);
    }
  else if (mode == MODE_RPMSIGN)
    {
      if (rpm_insertsig(&rpmrd, 0, buf + 6, outl))
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (outlh)
	{
	  if (rpm_insertsig(&rpmrd, 1, buf + 6 + outl, outlh))
	    {
	      if (!isfilter)
		unlink(outfilename);
	      exit(1);
	    }
	}
      if (!rpm_write(&rpmrd, foutfd, fd, chksumfilefd))
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      free(rpmrd.rpmsig);
      rpmrd.rpmsig = 0;
    }
  else if (mode == MODE_APPIMAGESIGN)
    appimage_write_signature(filename, buf + 6, outl);
  else
    fwrite(buf + 6, 1, outl, fout);

  if (!isfilter)
    {
      close(fd);
      if (fout && fclose(fout))
	{
	  perror("fclose");
	  unlink(outfilename);
	  exit(1);
	}
      if (mode != MODE_DETACHEDSIGN && mode != MODE_RAWDETACHEDSIGN
	  && mode != MODE_RAWOPENSSLSIGN && mode != MODE_APPIMAGESIGN
	  && rename(outfilename, filename))
	{
	  perror("rename");
	  unlink(outfilename);
	  exit(1);
	}
    }
  if (outfilename)
    free(outfilename);
  if (mode == MODE_RPMSIGN && chksumfilefd >= 0)
    rpm_writechecksums(&rpmrd, chksumfilefd);
  return 0;
}

static void
keygen(const char *type, const char *expire, const char *name,
       const char *email)
{
  const char *args[6];
  byte buf[8192];
  int l, publ, privl;
  int sock = opensocket();

  args[0] = "keygen";
  args[1] = algouser;
  args[2] = type;
  args[3] = expire;
  args[4] = name;
  args[5] = email;
  l = doreq(sock, 6, args, buf, sizeof(buf), 2);
  if (l < 0)
    exit(-l);
  publ = buf[2] << 8 | buf[3];
  privl = buf[4] << 8 | buf[5];
  if (privkey && strcmp(privkey, "-"))
    {
      int fout;
      char *outfilename = malloc(strlen(privkey) + 16);

      sprintf(outfilename, "%s.sIgN%d", privkey, getpid());
      if ((fout = open(outfilename, O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1)
	{
	  perror(outfilename);
	  exit(1);
	}
      if (write(fout, buf + 6 + publ, privl) != privl)
	{
	  perror("privkey write error");
	  exit(1);
	}
      if (write(fout, "\n", 1) != 1)
	{
	  perror("privkey write error");
	  exit(1);
	}
      if (close(fout))
	{
	  perror("privkey write error");
	  exit(1);
	}
      if (rename(outfilename, privkey))
	{
	  perror(privkey);
	  exit(1);
	}
    }
  else
    {
      if (fwrite(buf + 6 + publ, privl, 1, stdout) != 1)
	{
	  fprintf(stderr, "privkey write error\n");
	  exit(1);
	}
      printf("\n");
    }
  if (fwrite(buf + 6, publ, 1, stdout) != 1)
    {
      fprintf(stderr, "pubkey write error\n");
      exit(1);
    }
  if (fflush(stdout))
    {
      fprintf(stderr, "pubkey write error\n");
      exit(1);
    }
  exit(0);
}

void
keyextend(char *expire, char *pubkey)
{
  FILE *fp;
  char buf[8192];
  unsigned char rbuf[8192];
  unsigned char *pubk, *p, *pp;
  int i, l, ll, pubkl, tag, pl;
  unsigned char b[6];
  unsigned char *newpubk, *selfsigpkg;
  byte *issuer, *sigissuer;

  unsigned char *pk;
  int pkl;
  time_t pkcreat;
  unsigned char *userid;
  int useridl;

  int hl;
  unsigned char *ex;
  time_t now;
  int expdays;

  byte fingerprint[20];

  HASH_CONTEXT dig;
  unsigned char *digp;

  const char *args[5];
  char *bp;
  char hashhex[1024];
  int argc;
  int sock;
  byte *rsig;
  int rsigl, rsighl, rl;

  if (uid && !privkey)
    {
      fprintf(stderr, "need -P option for non-root operation\n");
      exit(1);
    }
  expdays = atoi(expire);
  if (expdays <= 0 || expdays >= 10000)
    {
      fprintf(stderr, "bad expire argument\n");
      exit(1);
    }
  if ((fp = fopen(pubkey, "r")) == 0)
    {
      perror(pubkey);
      exit(1);
    }
  l = 0;
  while (l < 8192 && (ll = fread(buf + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 8192)
    {
      fprintf(stderr, "pubkey too big\n");
      exit(1);
    }
  pubk = unarmor_pubkey(buf, &pubkl);
  if (!pubk)
    {
      fprintf(stderr, "could not parse pubkey armor\n");
      exit(1);
    }
  p = pubk;
  l = pubkl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 6)
    {
      fprintf(stderr, "pubkey does not start with a pubkey paket\n");
      exit(1);
    }
  if (*pp != 4)
    {
      fprintf(stderr, "pubkey is not type 4\n");
      exit(1);
    }
  pkcreat = pp[1] << 24 | pp[2] << 16 | pp[3] << 8 | pp[4];
  pk = pp;
  pkl = pl;
  calculatefingerprint(pk, pkl, fingerprint);

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 13)
    {
      fprintf(stderr, "missing userid\n");
      exit(1);
    }
  userid = pp;
  useridl = pl;

  selfsigpkg = p;
  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 2)
    {
      fprintf(stderr, "missing self-sig\n");
      exit(1);
    }
  if (pp[0] != 4)
    {
      fprintf(stderr, "self-sig is not type 4\n");
      exit(1);
    }
  if (pp[1] != 0x13)
    {
      fprintf(stderr, "self-sig is not class 0x13\n");
      exit(1);
    }
  if (pp[3] == 9 || pp[3] == 10 || pp[3] == 11)
    pp[3] = 8;	/* change sha384/512/224 to sha256 for now */
  if (pp[3] == 2)
    hashalgo = HASH_SHA1;
  else if (pp[3] == 8)
    hashalgo = HASH_SHA256;
  else
    {
      fprintf(stderr, "self-sig hash type is unsupported (algo %d)\n", pp[3]);
      exit(1);
    }
  if (algouser && algouser != user)
    free(algouser);
  if (hashalgo == HASH_SHA1)
    algouser = user;
  else
    {
      algouser = malloc(strlen(user) + strlen(hashname[hashalgo]) + 2);
      sprintf(algouser, "%s:%s", hashname[hashalgo], user);
    }
  if (pl < 6)
    {
      fprintf(stderr, "self-sig is too short\n");
      exit(1);
    }
  ex = findsubpkg(pp + 4, pl - 4, 2);
  if (!ex)
    {
      fprintf(stderr, "self-sig has no creation time\n");
      exit(1);
    }
  now = (u32)time((time_t)0);
  ex[0] = now >> 24;
  ex[1] = now >> 16;
  ex[2] = now >> 8;
  ex[3] = now;

  ex = findsubpkg(pp + 4, pl - 4, 9);
  if (!ex)
    {
      fprintf(stderr, "self-sig does not expire\n");
      exit(1);
    }
  now = (now - pkcreat) + expdays * (24 * 3600);
  ex[0] = now >> 24;
  ex[1] = now >> 16;
  ex[2] = now >> 8;
  ex[3] = now;

  issuer = findsigissuer(pp, pl);

  /* now create new digest */
  hash_init(&dig);
  b[0] = 0x99;
  b[1] = pkl >> 8;
  b[2] = pkl;
  hash_write(&dig, b, 3);
  hash_write(&dig, pk, pkl);
  b[0] = 0xb4;
  b[1] = useridl >> 24;
  b[2] = useridl >> 16;
  b[3] = useridl >> 8;
  b[4] = useridl;
  hash_write(&dig, b, 5);
  hash_write(&dig, userid, useridl);
  hl = 4 + 2 + ((pp[4] << 8) | pp[5]);
  if (hl > pl)
    {
      fprintf(stderr, "self-sig has bad hashed-length\n");
      exit(1);
    }
  hash_write(&dig, pp, hl);
  b[0] = 4;
  b[1] = 0xff;
  b[2] = hl >> 24;
  b[3] = hl >> 16;
  b[4] = hl >> 8;
  b[5] = hl;
  hash_write(&dig, b, 6);
  hash_final(&dig);
  digp = hash_read(&dig);

  hl += 2 + (pp[hl] << 8 | pp[hl + 1]);
  if (hl > pl)
    {
      fprintf(stderr, "self-sig has bad length\n");
      exit(1);
    }

  now = (u32)time((time_t)0);
  b[0] = 0;
  b[1] = now >> 24;
  b[2] = now >> 16;
  b[3] = now >> 8;
  b[4] = now;

  if (privkey)
    readprivkey();
  bp = hashhex;
  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
    sprintf((char *)bp, "%02x", digp[i]);
  *bp++ = '@';
  for (i = 0; i < 5; i++, bp += 2)
    sprintf((char *)bp, "%02x", b[i]);
  *bp = 0;
  args[0] = privkey ? "privsign" : "sign";
  args[1] = algouser;
  argc = 2;
  if (privkey)
    args[argc++] = privkey;
  args[argc++] = hashhex;
  sock = opensocket();
  rl = doreq(sock, argc, args, rbuf, sizeof(rbuf), 1);
  if (rl < 0)
    exit(-rl);
  rsig = pkg2sig(rbuf + 4, rbuf[2] << 8 | rbuf[3], &rsigl);
  sigissuer = findsigissuer(rsig, rsigl);
  if (issuer && sigissuer && memcmp(issuer, sigissuer, 8))
    {
      fprintf(stderr, "issuer does not match, did you forget -P?\n");
      exit(1);
    }
  if (memcmp(fingerprint + 12, sigissuer, 8))
    {
      fprintf(stderr, "fingerprint does not match self sig\n");
      exit(1);
    }
  rsighl = findsigmpioffset(rsig, rsigl) - 2;	/* subtract 2 for hash bits */
  /*
   * pp: self-sig
   * pl: length of self-sig
   * hl: offset of left 16 bits of hash in v4 self-sig
   * rsig: new v3 sig
   * rsigl: length of new v3 sig
   * rsighl: offset of left 16 bits of hash in new v3 sig
   */
  newpubk = malloc((selfsigpkg - pubk) + 4 + hl + (rsigl - rsighl));
  memcpy(newpubk, pubk, selfsigpkg - pubk);
  /* leave 4 bytes space for pkg header */
  memcpy(newpubk + (selfsigpkg - pubk) + 4, pp, hl);
  memcpy(newpubk + (selfsigpkg - pubk) + 4 + hl, rsig + rsighl, rsigl - rsighl);
  pp = addpkg(newpubk + (selfsigpkg - pubk), newpubk + (selfsigpkg - pubk) + 4, hl + (rsigl - rsighl), 2, selfsigpkg[0] & 64);
  /* add remaining packages that come after the v4 self-sig */
  if (l)
    {
      memcpy(pp, p, l);
      pp += l;
    }
  write_armored_pubkey(stdout, newpubk, pp - newpubk);
  free(newpubk);
}

static void
certsizelimit(char *s, int l)
{
  if (strlen(s) <= l)
    return;
  s[l] = 0;
  s[l - 1] = s[l - 2] = s[l - 3] = '.';
}

void
initrandom()
{
  unsigned int seed = 0x23468676;
  struct timeval tv;
  gettimeofday(&tv, 0);
  seed ^= (int)tv.tv_sec;
  seed ^= (int)tv.tv_usec;
  seed ^= (int)getpid() * 37;
  srandom(seed);
}

void
createcert(char *pubkey)
{
  struct certbuf cb;
  FILE *fp;
  char buf[8192];
  unsigned char rbuf[8192];
  char hashhex[1024];
  unsigned char *pubk;
  int pubkl;
  unsigned char *p, *pp;
  int i, l, ll, tag, pl;
  time_t pkcreat, now, beg, exp;
  unsigned char *ex;
  unsigned char *userid;
  int useridl;
  const char *args[6];
  int argc;
  int sock;
  int rl;
  char *name, *nameend;
  char *email;
  byte *mpin, *mpie;
  int mpinl, mpiel;
  byte *rawssl;
  int rawssllen;
  HASH_CONTEXT ctx;
  byte *sigissuer, fingerprint[20];
  int sigl;
  byte *sig;

  if (uid && !privkey)
    {
      fprintf(stderr, "need -P option for non-root operation\n");
      exit(1);
    }
  if (privkey)
    readprivkey();
  if ((fp = fopen(pubkey, "r")) == 0)
    {
      perror(pubkey);
      exit(1);
    }
  l = 0;
  while (l < 8192 && (ll = fread(buf + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 8192)
    {
      fprintf(stderr, "pubkey too big\n");
      exit(1);
    }
  pubk = unarmor_pubkey(buf, &pubkl);
  if (!pubk)
    {
      fprintf(stderr, "could not parse pubkey armor\n");
      exit(1);
    }
  p = pubk;
  l = pubkl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 6)
    {
      fprintf(stderr, "pubkey does not start with a pubkey paket\n");
      exit(1);
    }
  if (pp[0] != 4)
    {
      fprintf(stderr, "pubkey is not type 4\n");
      exit(1);
    }
  if (pp[5] != 1)
    {
      fprintf(stderr, "not a RSA pubkey\n");
      exit(1);
    }
  calculatefingerprint(pp, pl, fingerprint);

  /* get creattion time */
  pkcreat = pp[1] << 24 | pp[2] << 16 | pp[3] << 8 | pp[4];

  /* get MPIs */
  mpin = pp + 8;
  mpinl = ((mpin[-2] << 8 | mpin[-1]) + 7) / 8;
  mpie = mpin + 2 + mpinl;
  mpiel = ((mpie[-2] << 8 | mpie[-1]) + 7) / 8;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 13)
    {
      fprintf(stderr, "missing userid\n");
      exit(1);
    }
  userid = pp;
  useridl = pl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 2)
    {
      fprintf(stderr, "missing self-sig\n");
      exit(1);
    }
  if (pp[0] != 4)
    {
      fprintf(stderr, "self-sig is not type 4\n");
      exit(1);
    }
  if (pp[1] != 0x13)
    {
      fprintf(stderr, "self-sig is not class 0x13\n");
      exit(1);
    }
  if (pl < 6)
    {
      fprintf(stderr, "self-sig is too short\n");
      exit(1);
    }
  ex = findsubpkg(pp + 4, pl - 4, 2);
  if (!ex)
    {
      fprintf(stderr, "self-sig has no creation time\n");
      exit(1);
    }
  beg = (ex[0] << 24 | ex[1] << 16 | ex[2] << 8 | ex[3]);
  now = (u32)time((time_t)0);
  if (beg > now)
    beg = now;
  ex = findsubpkg(pp + 4, pl - 4, 9);
  if (!ex)
    {
      fprintf(stderr, "self-sig does not expire\n");
      exit(1);
    }
  exp = pkcreat + (ex[0] << 24 | ex[1] << 16 | ex[2] << 8 | ex[3]);
  if (exp < now)
    {
      fprintf(stderr, "pubkey is already expired\n");
      exit(1);
    }
  
  name = malloc(useridl + 1);
  if (!name)
    {
      fprintf(stderr, "out of mem\n");
      exit(1);
    }
  strncpy(name, (char *)userid, useridl);
  name[useridl] = 0;
  if (!useridl || name[useridl - 1] != '>')
    {
      fprintf(stderr, "userid does not end with email\n");
      exit(1);
    }
  name[useridl - 1] = 0;
  email = strrchr(name, '<');
  if (!email || email == name)
    {
      fprintf(stderr, "userid does not end with email\n");
      exit(1);
    }
  nameend = email;
  *email++ = 0;
  while (nameend > name && (nameend[-1] == ' ' || nameend[-1] == '\t'))
    *--nameend = 0;
  /* limit to fixed sizes, see rfc 3280 */
  certsizelimit(name, 64);
  certsizelimit(email, 128);

  /* create tbscert */
  memset(&cb, 0, sizeof(cb));
  certbuf_tbscert(&cb, name, email, beg, exp, mpin, mpinl, mpie, mpiel);
  free(name);
  free(pubk);

  /* self-sign it */
  hash_init(&ctx);
  hash_write(&ctx, cb.buf, cb.len);
  hash_final(&ctx);
  p = hash_read(&ctx);
  for (i = 0; i < hashlen[hashalgo]; i++)
    sprintf(hashhex + i * 2, "%02x", p[i]);
  strcpy(hashhex + i * 2, "@0000000000");
  args[0] = privkey ? "privsign" : "sign";
  args[1] = algouser;
  argc = 2;
  if (privkey)
    args[argc++] = privkey;
  args[argc++] = hashhex;
  sock = opensocket();
  rl = doreq(sock, argc, args, rbuf, sizeof(rbuf), 1);
  if (rl < 0)
    exit(-rl);

  sig = pkg2sig(rbuf + 4, rbuf[2] << 8 | rbuf[3], &sigl);
  sigissuer = findsigissuer(sig, sigl);
  if (sigissuer && memcmp(sigissuer, fingerprint + 12, 8))
    {
      fprintf(stderr, "signature issuer does not match fingerprint\n");
      exit(1);
    }
  /* get signnature */
  rawssl = getrawopensslsig(sig, sigl, &rawssllen);

  /* finish cert */
  certbuf_finishcert(&cb, rawssl, rawssllen);
  free(rawssl);

  /* print as PEM */
  printf("-----BEGIN CERTIFICATE-----\n");
  printr64(stdout, cb.buf, cb.len);
  printf("-----END CERTIFICATE-----\n");
  free(cb.buf);
}

void
ping()
{
  byte buf[256];
  int r, sock = opensocket();
  memset(buf, 0, 4);
  r = doreq_old(sock, buf, 4, sizeof(buf));
  if (r)
    exit(-r);
}

void
read_sign_conf(const char *conf)
{
  FILE *cfp;
  char buf[256], *bp;
  int c, l;
  struct passwd *pwd = 0;

  if (uid)
    pwd = getpwuid(uid);
  if ((cfp = fopen(conf, "r")) == 0)
    {
      perror(conf);
      exit(1);
    }
  while (fgets(buf, sizeof(buf), cfp))
    {
      l = strlen(buf);
      if (!l)
	continue;
      if (buf[l - 1] != '\n')
	{
	  while ((c = getc(cfp)) != EOF)
	    if (c == '\n')
	      break;
	  continue;
	}
      if (*buf == '#')
	continue;
      buf[--l] = ' ';
      while (l && (buf[l] == ' ' || buf[l] == '\t'))
	buf[l--] = 0;
      for (bp = buf; *bp && *bp != ':'; bp++)
	;
      if (!*bp)
	continue;
      *bp++ = 0;
      while (*bp == ' ' || *bp == '\t')
	bp++;
      if (!strcmp(buf, "user"))
	{
	  user = strdup(bp);
	  continue;
	}
      if (!strcmp(buf, "server"))
	{
	  host = strdup(bp);
	  continue;
	}
      if (!strcmp(buf, "port"))
	{
	  port = atoi(bp);
	  continue;
	}
      if (!strcmp(buf, "hash"))
	{
	  if (!strcasecmp(bp, "sha1"))
	    hashalgo = HASH_SHA1;
	  else if (!strcasecmp(bp, "sha256"))
	    hashalgo = HASH_SHA256;
	  else
	    {
	      fprintf(stderr, "sign: hash: unknown argument\n");
	      exit(1);
	    }
	}
      if (uid && !allowuser && !strcmp(buf, "allowuser"))
	{
	  if (pwd && !strcmp(pwd->pw_name, bp))
	    allowuser = 1;
	  else
	    {
	      long int li;
	      char *ep = 0;
	      li = strtol(bp, &ep, 10);
	      if (*ep == 0 && li == (long int)uid)
		allowuser = 1;
	    }
	}
    }
  fclose(cfp);
}

void usage()
{
    fprintf(stderr, "usage:  sign [-v] [options]\n\n"
            "  sign [-v] -c <file> [-u user] [-h hash]: add clearsign signature\n"
            "  sign [-v] -d <file> [-u user] [-h hash]: create detached signature\n"
            "  sign [-v] -r <file> [-u user] [-h hash]: add signature block to rpm\n"
            "  sign [-v] -a <file> [-u user] [-h hash]: add signature block to appimage\n"
            "  sign [-v] -k [-u user] [-h hash]: print key id\n"
            "  sign [-v] -p [-u user] [-h hash]: print public key\n"
            "  sign [-v] -g <type> <expire> <name> <email>: generate keys\n"
            "  sign [-v] -x <expire> <pubkey>: extend pubkey\n"
            "  sign [-v] -C <pubkey>: create certificate\n"
            "  sign [-v] -t: test connection to signd server\n"
            //"  -D: RAWDETACHEDSIGN\n"
            //"  -O: RAWOPENSSLSIGN\n"
            //"  --noheaderonly\n"
            //"  -S <file>: verify checksum\n"
            //"  -T  time?\n"
            //"  -P  privkey\n" 
            "\n"
           );
}

int
main(int argc, char **argv)
{
  int mode = MODE_UNSET;
  const char *conf = 0;

  uid = getuid();
  user = strdup("");
  host = strdup("127.0.0.1");

  if (argc > 2 && !strcmp(argv[1], "--test-sign"))
    {
      test_sign = argv[2];
      argc -= 2;
      argv += 2;
      conf = getenv("SIGN_CONF");
      allowuser = 1;
    }
  read_sign_conf(conf ? conf : "/etc/sign.conf");

  if (uid)
    {
      if (!allowuser)
	{
	  fprintf(stderr, "sign: permission denied\n");
	  exit(1);
	}
      if (seteuid(uid))
	{
	  perror("seteuid");
	  exit(1);
	}
    }
  if (argc == 2 && !strcmp(argv[1], "-t"))
    {
      ping();
      exit(0);
    }
  while (argc > 1)
    {
      if (!strcmp(argv[1], "--help"))
        {
          usage();
          exit(0);
        }
      else if (argc > 2 && !strcmp(argv[1], "-u"))
	{
	  user = argv[2];
	  argc -= 2;
	  argv += 2;
	}
      else if (argc > 2 && !strcmp(argv[1], "-h"))
	{
	  if (!strcasecmp(argv[2], "sha1"))
	    hashalgo = HASH_SHA1;
	  else if (!strcasecmp(argv[2], "sha256"))
	    hashalgo = HASH_SHA256;
	  else
	    {
	      fprintf(stderr, "sign: unknown hash algorithm '%s'\n", argv[2]);
	      exit(1);
	    }
	  argc -= 2;
	  argv += 2;
	}
      else if (argc > 1 && !strcmp(argv[1], "-c"))
	{
	  mode = MODE_CLEARSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-d"))
	{
	  mode = MODE_DETACHEDSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-D"))
	{
	  mode = MODE_RAWDETACHEDSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-O"))
	{
	  mode = MODE_RAWOPENSSLSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-r"))
	{
	  mode = MODE_RPMSIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-a"))
	{
	  mode = MODE_APPIMAGESIGN;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "-v"))
	{
	  verbose++;
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(argv[1], "--noheaderonly"))
        {
	  noheaderonly = 1;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-k"))
        {
	  mode = MODE_KEYID;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-p"))
        {
	  mode = MODE_PUBKEY;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-g"))
        {
	  mode = MODE_KEYGEN;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-x"))
        {
	  mode = MODE_KEYEXTEND;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-C"))
        {
	  mode = MODE_CREATECERT;
	  argc--;
	  argv++;
	}
      else if (argc > 2 && !strcmp(argv[1], "-S"))
	{
	  chksumfile = argv[2];
	  argc -= 2;
	  argv += 2;
	}
      else if (argc > 2 && !strcmp(argv[1], "-T"))
	{
	  timearg = argv[2];
	  argc -= 2;
	  argv += 2;
	  if (!*timearg || ((*timearg < '0' || *timearg > '9') && strcmp(timearg, "mtime") && strcmp(timearg, "buildtime")))
	    {
	      fprintf(stderr, "illegal time argument: %s\n", timearg);
	      exit(1);
	    }
	}
      else if (argc > 2 && !strcmp(argv[1], "-P"))
        {
	  privkey = argv[2];
	  argc -= 2;
	  argv += 2;
        }
      else if (argc > 1 && !strcmp(argv[1], "--pkcs1pss"))
        {
	  pkcs1pss = 1;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "-4"))
        {
	  dov4sig = 1;
	  argc--;
	  argv++;
        }
      else if (argc > 1 && !strcmp(argv[1], "--"))
        {
	  argc--;
	  argv++;
	  break;
        }
      else if (argc > 1 && argv[1][0] == '-')
	{
	  usage();
	  exit(1);
	}
      else
        break;
    }
  if (mode == MODE_CREATECERT)
    hashalgo = HASH_SHA256;	/* always sign certs with sha256 */
  if (hashalgo == HASH_SHA1)
    algouser = user;
  else
    {
      algouser = malloc(strlen(user) + strlen(hashname[hashalgo]) + 2);
      sprintf(algouser, "%s:%s", hashname[hashalgo], user);
    }
  if ((mode == MODE_KEYID || mode == MODE_PUBKEY) && argc > 1)
    {
      fprintf(stderr, "usage: sign [-c|-d|-r|-a] [-u user] <file>\n");
      exit(1);
    }
  if (pkcs1pss && mode != MODE_RAWOPENSSLSIGN)
    {
      fprintf(stderr, "can only generate a pkcs1pss signature in openssl mode\n");
      exit(1);
    }
  if (mode == MODE_KEYGEN)
    {
      if (argc != 5)
	{
	  fprintf(stderr, "usage: sign -g <type> <expire> <name> <email>\n");
	  exit(1);
	}
      keygen(argv[1], argv[2], argv[3], argv[4]);
      exit(0);
    }
  if (mode == MODE_KEYEXTEND)
    {
      if (argc != 3)
	{
	  fprintf(stderr, "usage: sign -x <expire> <pubkey>\n");
	  exit(1);
	}
      keyextend(argv[1], argv[2]);
      exit(0);
    }
  if (mode == MODE_CREATECERT)
    {
      initrandom();
      if (argc != 2)
	{
	  fprintf(stderr, "usage: sign -C <pubkey>\n");
	  exit(1);
	}
      createcert(argv[1]);
      exit(0);
    }
  if (privkey && access(privkey, R_OK))
    {
      perror(privkey);
      exit(1);
    }

  if (dov4sig && mode != MODE_KEYID && mode != MODE_PUBKEY && mode != MODE_RAWOPENSSLSIGN)
    pubalgoprobe = probe_pubalgo();

  if (chksumfile)
    {
      if (strcmp(chksumfile, "-"))
	chksumfilefd = open(chksumfile, O_WRONLY|O_CREAT|O_APPEND, 0666);
      else
	chksumfilefd = 1;
      if (chksumfilefd < 0)
	{
	  perror(chksumfile); 
	  exit(1);
	}
    }
  if (argc == 1)
    sign("<stdin>", 1, mode);
  else while (argc > 1)
    {
      sign(argv[1], 0, mode);
      argv++;
      argc--;
    }
  if (chksumfile && strcmp(chksumfile, "-") && chksumfilefd >= 0)
    {
      if (close(chksumfilefd))
	{
	  perror("chksum file close");
	  exit(1);
	}
    }
  exit(0);
}

