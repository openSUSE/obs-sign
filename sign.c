/*
 * Copyright (c) 2006-2022 SUSE LLC
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pwd.h>

#include "inc.h"

char *host;
int port = MYPORT;
char *test_sign;
int allow_unprivileged_ports = 0;
static char *user;
static char *algouser;
static int allowuser;
static int verbose;
uid_t uid;

static const char *const hashname[] = {"SHA1", "SHA256", "SHA512"};
static const int  hashlen[] = {20, 32, 64};

static const char *const pubalgoname[] = {"DSA", "RSA", "EdDSA"};

int hashalgo = HASH_SHA1;
int assertpubalgo = -1;
static const char *timearg;
static char *privkey;
static int privkey_read;
static int noheaderonly;
static int pkcs1pss;
static char *chksumfile;
static int chksumfilefd = -1;
static int dov4sig;
static int pubalgoprobe = -1;
static struct x509 cert;
static struct x509 othercerts;
int appxdetached = 0;
static int cms_flags = 0;

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
#define MODE_APPXSIGN	  12
#define MODE_HASHFILE	  13
#define MODE_CMSSIGN	  14
#define MODE_PESIGN	  15
#define MODE_KOSIGN	  16

static const char *const modes[] = {
  "?", "rpm sign", "clear sign", "detached sign", "keyid", "pubkey", "keygen", "keyextend",
  "raw detached sign", "raw openssl sign", "cert create", "appimage sign", "appx sign", "hashfile",
  "cms sign", "PE sign", "kernel module sign"
};

static void
readprivkey(void)
{
  FILE *fp;
  int l, ll;
  if (privkey_read)
    return;
  if ((fp = fopen(privkey, "r")) == 0)
    dodie_errno(privkey);
  privkey_read = 1;
  privkey = doalloc(8192);
  *privkey = 0;
  l = 0;
  while (l < 8192 && (ll = fread(privkey + l, 1, 8192 - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == 0)
    dodie("empty private key");
  if (l == 8192)
    dodie("private key too large");
  if (privkey[l - 1] == '\n')
    l--;
  privkey[l] = 0;
}

static int
probe_pubalgo()
{
  char hashhex[1024];
  byte buf[8192], *bp;
  u32 signtime = time(NULL);
  int i, ulen, outl;

  opensocket();
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
	  closesocket();
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
      outl = doreq_old(buf, (int)(bp - buf), sizeof(buf));
    }
  else
    {
      const char *args[5];

      readprivkey();
      args[0] = "privsign";
      args[1] = algouser;
      args[2] = privkey;
      args[3] = hashhex;
      outl = doreq(4, args, buf, sizeof(buf), 1);
      if (outl >= 0)
	{
	  outl = buf[2] << 8 | buf[3];
	  memmove(buf, buf + 4, outl);
	}
    }
  return outl > 0 ? pkg2sigpubalgo(buf, outl) : -1;
}

static byte *
digest2arg(byte *bp, byte *dig, byte *sigtrail)
{
  int i;
  for (i = 0; i < hashlen[hashalgo]; i++, bp += 2)
    sprintf((char *)bp, "%02x", dig[i]);
  *bp++ = '@';
  for (i = 0; i < 5; i++, bp += 2)
    sprintf((char *)bp, "%02x", sigtrail[i]);
  return bp;
}

static int
slurp(char *filename, char *buf, int bufl)
{
  int l, ll;
  FILE *fp;
  if ((fp = fopen(filename, "r")) == 0)
    dodie_errno(filename);
  l = 0;
  while (l < bufl && (ll = fread(buf + l, 1, bufl - l, fp)) > 0)
    l += ll;
  fclose(fp);
  if (l == bufl)
    {
      fprintf(stderr, "%s: too big, max size: %d\n", filename, bufl - 1);
      exit(1);
    }
  buf[l] = 0;	/* convenience */
  return l;
}

static int
plainsign_read(int fd, char *filename, HASH_CONTEXT *ctx)
{
  byte buf[8192];
  for (;;)
    {
      int l = read(fd, buf, sizeof(buf));
      if (l < 0)
	dodie_errno(filename);
      if (l == 0)
	break;
      hash_write(ctx, buf,  l);
    }
  return 1;
}

static int
sign(char *filename, int isfilter, int mode)
{
  u32 signtime;
  struct rpmdata rpmrd;
  struct appxdata appxdata;
  struct pedata pedata;
  byte buf[8192];
  int l, fd;
  byte sigtrail[5], *p, *ph = 0;
  HASH_CONTEXT ctx;
  HASH_CONTEXT hctx;
  int force = 1;
  int outl, outlh;
  char *outfilename = 0;
  char *finaloutfilename = 0;	/* rename outfilename to finaloutfilename when done */
  FILE *fout = 0;
  int getbuildtime = 0;
  unsigned char *v4sigtrail = 0;
  int v4sigtraillen = 0;
  struct x509 cms_signedattrs;
  int needsign;
  int rawssllen;
  byte *rawssl;

  if (mode == MODE_UNSET)
    {
      force = 0;
      if (isfilter)
	dodie("please specify a mode for filter usage (see sign --help)");
      l = strlen(filename);
      if (l > 4 && (!strcmp(filename + l - 4, ".rpm") || !strcmp(filename + l - 4, ".spm")))
	mode = MODE_RPMSIGN;
      else if (l > 9 && (!strcmp(filename + l - 9, ".AppImage")))
        mode = MODE_APPIMAGESIGN;
      else if (l > 5 && (!strcmp(filename + l - 5, ".appx")))
        mode = MODE_APPXSIGN;
      else
        mode = MODE_CLEARSIGN;
    }

  if (mode == MODE_APPIMAGESIGN && isfilter)
    dodie("appimage sign cannot work as filter");

  /* make sure we have a cert for appx/cms sign */
  if (mode == MODE_APPXSIGN || mode == MODE_CMSSIGN || mode == MODE_PESIGN || mode == MODE_KOSIGN)
    {
      int pubalgo;
      if (!cert.len)
	{
	  fprintf(stderr, "need a cert for %s\n", modes[mode]);
	  exit(1);
	}
      pubalgo = x509_cert2pubalgo(&cert);
      if (assertpubalgo < 0)
	assertpubalgo = pubalgo;
      if (assertpubalgo != pubalgo)
	dodie("pubkey algorithm does not match cert");
    }

  /* open input file */
  if (isfilter)
    fd = 0;
  else if ((fd = open(filename, O_RDONLY)) == -1)
    dodie_errno(filename);

  /* calculate output file name (but do not open yet) */
  if (!isfilter && mode != MODE_APPIMAGESIGN)
    {
      outfilename = doalloc(strlen(filename) + 16);
      if (mode == MODE_DETACHEDSIGN)
	sprintf(outfilename, "%s.asc", filename);
      else if (mode == MODE_RAWDETACHEDSIGN || mode == MODE_RAWOPENSSLSIGN)
	sprintf(outfilename, "%s.sig", filename);
      else if (mode == MODE_CMSSIGN)
	sprintf(outfilename, "%s.p7s", filename);
      else if (mode == MODE_APPXSIGN && appxdetached)
	sprintf(outfilename, "%s.p7x", filename);
      else
	{
	  sprintf(outfilename, "%s.sIgN%d", filename, getpid());
	  finaloutfilename = filename;
	}
    }

  /* set sign time */
  if (!timearg || mode == MODE_KEYID)
    signtime = time(NULL);
  else if (*timearg >= '0' && *timearg <= '9')
    signtime = strtoul(timearg, NULL, 0);
  else if (mode == MODE_RPMSIGN && !strcmp(timearg, "buildtime"))
    {
      getbuildtime = 1;
      signtime = 0;		/* rpmsign && buildtime */
    }
  else	/* timearg is buildtime or mtime */
    {
      struct stat stb;
      if (fstat(fd, &stb))
        dodie_errno("fstat");
      if (S_ISFIFO(stb.st_mode))
	dodie("cannot use mtime on pipes");
      signtime = stb.st_mtime;
    }

  needsign = 0;
  hash_init(&ctx);
  if (mode == MODE_CLEARSIGN)
    {
      /* clearsign is somewhat special: it can open fout */
      needsign = clearsign(fd, filename, outfilename, &ctx, hashname[hashalgo], isfilter, force, &fout);
    }
  else if (mode == MODE_KEYID)
    needsign = 1;	/* sign an empty string */
  else if (mode == MODE_APPXSIGN)
    needsign = appx_read(&appxdata, fd, filename, &ctx, signtime);
  else if (mode == MODE_PESIGN)
    needsign = pe_read(&pedata, fd, filename, &ctx, signtime);
  else if (mode == MODE_KOSIGN)
    needsign = ko_read(fd, filename, &ctx);
  else if (mode == MODE_APPIMAGESIGN)
    needsign = appimage_read(filename, &ctx);
  else if (mode == MODE_RPMSIGN)
    {
      needsign = rpm_read(&rpmrd, fd, filename, &ctx, &hctx, getbuildtime);
      if (getbuildtime)
	signtime = rpmrd.buildtime;
    }
  else
    needsign = plainsign_read(fd, filename, &ctx);

  if (!needsign)
    {
      fprintf(isfilter ? stderr : stdout, "%s: already signed\n", filename);
      close(fd);
      if (outfilename)
	free(outfilename);
      if (isfilter)
	exit(1);
      return 1;
    }
  /* open the socket and connect to signd (clearsign already opened it) */
  if (mode != MODE_CLEARSIGN)
    opensocket();

  if (mode == MODE_CMSSIGN || mode == MODE_KOSIGN)
    {
      x509_init(&cms_signedattrs);
      if (signtime)
	{
	  hash_final(&ctx);
	  x509_signedattrs(&cms_signedattrs, hash_read(&ctx), hash_len(), signtime);
	  hash_init(&ctx);
	  hash_write(&ctx, cms_signedattrs.buf, cms_signedattrs.len);
	}
    }

  if (verbose && mode != MODE_KEYID)
    {
      if (*user)
        fprintf(isfilter ? stderr : stdout, "%s %s user %s\n", modes[mode],  filename, user);
      else
        fprintf(isfilter ? stderr : stdout, "%s %s\n", modes[mode],  filename);
    }

  /* finalize the hash for gpg signatures */
  if (mode == MODE_RAWOPENSSLSIGN || mode == MODE_APPXSIGN || mode == MODE_PESIGN || mode == MODE_KOSIGN || mode == MODE_CMSSIGN)
    {
      sigtrail[0] = pkcs1pss ? 0xbc : 0x00;
      sigtrail[1] = sigtrail[2] = sigtrail[3] = sigtrail[4] = 0;	/* time does not matter */
    }
  else
    {
      if (dov4sig)
        v4sigtrail = genv4sigtrail(mode == MODE_CLEARSIGN ? 1 : 0, pubalgoprobe >= 0 ? pubalgoprobe : PUB_RSA, hashalgo, signtime, &v4sigtraillen);
      sigtrail[0] = mode == MODE_CLEARSIGN ? 0x01 : 0x00; /* class */
      sigtrail[1] = signtime >> 24;
      sigtrail[2] = signtime >> 16;
      sigtrail[3] = signtime >> 8;
      sigtrail[4] = signtime;
      if (v4sigtrail)
        hash_write(&ctx, v4sigtrail, v4sigtraillen);
      else
        hash_write(&ctx, sigtrail, 5);
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
        hash_write(&hctx, sigtrail, 5);
      hash_final(&hctx);
      /* header only seems to work only if there's a header only hash */
      if (!noheaderonly && rpmrd.gotsha1)
        ph = hash_read(&hctx);
    }

  if (!privkey && !ph)
    {
      /* old style sign */
      int ulen = strlen(user);
      byte *bp;
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
      bp = digest2arg(bp, p, sigtrail);
      buf[3] = bp - (buf + 4 + ulen);
      outl = doreq_old(buf, (int)(bp - buf), sizeof(buf));
      if (outl >= 0)
        memmove(buf + 6, buf, outl);	/* make 1st arg start at offset 6, we know there is room */
    }
  else
    {
      /* new style sign with doreq */
      const char *args[5];
      char hashhex[1024];
      char hashhexh[1024];
      int argc;

      if (privkey)
        readprivkey();
      digest2arg((byte *)hashhex, p, sigtrail);
      if (ph)
        digest2arg((byte *)hashhexh, ph, sigtrail);
      args[0] = privkey ? "privsign" : "sign";
      args[1] = algouser;
      argc = 2;
      if (privkey)
        args[argc++] = privkey;
      args[argc++] = hashhex;
      if (ph)
        args[argc++] = hashhexh;
      outl = doreq(argc, args, buf, sizeof(buf), ph ? 2 : 1);
      if (outl >= 0)
	{
	  outl = buf[2] << 8 | buf[3];
	  outlh = ph ? (buf[4] << 8 | buf[5]) : 0;
	  if (outl == 0 || (ph && outlh == 0))
	    {
	      if (mode == MODE_CLEARSIGN && !isfilter)
		unlink(outfilename);
	      dodie("server returned empty signature");
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

  if (assertpubalgo >= 0)
    {
      int sigpubalgo = pkg2sigpubalgo(buf + 6, outl);
      if (sigpubalgo < 0)
	dodie("unknown public key algorithm in signature");
      if (assertpubalgo != sigpubalgo)
	{
	  fprintf(stderr, "unexpected public key algorithm: wanted %s, got %s\n", pubalgoname[assertpubalgo], pubalgoname[sigpubalgo]);
	  exit(1);
	}
    }

  if (mode == MODE_KEYID)
    {
      int sigl;
      byte *sig = pkg2sig(buf + 6, outl, &sigl);
      byte *issuer = findsigissuer(sig, sigl);
      if (!issuer)
	dodie("issuer not found in signature");
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

  /* finally open the output file */
  if (isfilter)
    fout = stdout;
  else if (mode != MODE_CLEARSIGN && mode != MODE_APPIMAGESIGN)
    {
      if ((fout = fopen(outfilename, "w")) == 0)
	dodie_errno(outfilename);
    }

  /* find raw openssl signature if needed */
  rawssllen = 0;
  rawssl = 0;
  if (mode == MODE_RAWOPENSSLSIGN || mode == MODE_APPXSIGN || mode == MODE_PESIGN || mode == MODE_CMSSIGN || mode == MODE_KOSIGN)
    {
      int sigl;
      byte *sig = pkg2sig(buf + 6, outl, &sigl);
      rawssl = getrawopensslsig(sig, sigl, &rawssllen);
      if (!rawssl)
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
    }

  /* write/incorporate signature */
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
      if (fwrite(rawssl, rawssllen, 1, fout) != 1)
	{
	  perror("fwrite");
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
    }
  else if (mode == MODE_RPMSIGN)
    {
      if (rpm_insertsig(&rpmrd, 0, buf + 6, outl))
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      if (outlh && rpm_insertsig(&rpmrd, 1, buf + 6 + outl, outlh))
	{
	  if (!isfilter)
	    unlink(outfilename);
	  exit(1);
	}
      rpm_write(&rpmrd, isfilter ? 1 : fileno(fout), fd, chksumfilefd);
      rpm_free(&rpmrd);
    }
  else if (mode == MODE_APPIMAGESIGN)
    appimage_write_signature(filename, buf + 6, outl);
  else if (mode == MODE_APPXSIGN)
    {
      appx_write(&appxdata, isfilter ? 1 : fileno(fout), fd, &cert, rawssl, rawssllen, &othercerts);
      appx_free(&appxdata);
    }
  else if (mode == MODE_PESIGN)
    {
      pe_write(&pedata, isfilter ? 1 : fileno(fout), fd, &cert, rawssl, rawssllen, &othercerts);
      pe_free(&pedata);
    }
  else if (mode == MODE_CMSSIGN)
    {
      struct x509 cb;
      x509_init(&cb);
      x509_pkcs7_signed_data(&cb, 0, (cms_signedattrs.len ? &cms_signedattrs : 0), rawssl, rawssllen, &cert, &othercerts, cms_flags);
      fwrite(cb.buf, 1, cb.len, fout);
      x509_free(&cb);
      x509_free(&cms_signedattrs);
    }
  else if (mode == MODE_KOSIGN)
    {
      struct x509 cb;
      x509_init(&cb);
      x509_pkcs7_signed_data(&cb, 0, (cms_signedattrs.len ? &cms_signedattrs : 0), rawssl, rawssllen, &cert, &othercerts, cms_flags | X509_PKCS7_NO_CERTS);
      ko_write(isfilter ? 1 : fileno(fout), fd, &cb);
      x509_free(&cb);
      x509_free(&cms_signedattrs);
    }
  else
    fwrite(buf + 6, 1, outl, fout);

  if (rawssl)
    free(rawssl);

  /* close and rename output file */
  if (!isfilter)
    {
      close(fd);
      if (fout && fclose(fout))
	{
	  perror("fclose");
	  unlink(outfilename);
	  exit(1);
	}
      if (finaloutfilename && rename(outfilename, finaloutfilename) != 0)
	{
	  perror("rename");
	  unlink(outfilename);
	  exit(1);
	}
    }
  if (outfilename)
    free(outfilename);

  /* append to checksums file if needed */
  if (mode == MODE_RPMSIGN && chksumfilefd >= 0)
    rpm_writechecksums(&rpmrd, chksumfilefd);

  return 0;
}

static void
keygen(const char *type, const char *expire, const char *name, const char *email)
{
  const char *args[6];
  byte buf[8192];
  int l, publ, privl;

  opensocket();
  args[0] = "keygen";
  args[1] = algouser;
  args[2] = type;
  args[3] = expire;
  args[4] = name;
  args[5] = email;
  l = doreq(6, args, buf, sizeof(buf), 2);
  if (l < 0)
    exit(-l);
  publ = buf[2] << 8 | buf[3];
  privl = buf[4] << 8 | buf[5];
  if (privkey && strcmp(privkey, "-"))
    {
      int fout;
      char *outfilename = doalloc(strlen(privkey) + 16);

      sprintf(outfilename, "%s.sIgN%d", privkey, getpid());
      if ((fout = open(outfilename, O_WRONLY|O_CREAT|O_TRUNC, 0600)) == -1)
	dodie_errno(outfilename);
      if (write(fout, buf + 6 + publ, privl) != privl)
	dodie_errno("privkey write error");
      if (write(fout, "\n", 1) != 1)
	dodie_errno("privkey write error");
      if (close(fout))
	dodie_errno("privkey write error");
      if (rename(outfilename, privkey))
	dodie_errno(privkey);
    }
  else
    {
      if (fwrite(buf + 6 + publ, privl, 1, stdout) != 1)
	dodie_errno("privkey write error");
      printf("\n");
    }
  if (fwrite(buf + 6, publ, 1, stdout) != 1)
    dodie_errno("pubkey write error");
  if (fflush(stdout))
    dodie_errno("pubkey write error");
  exit(0);
}

void
keyextend(char *expire, char *pubkey)
{
  char buf[8192];
  unsigned char rbuf[8192];
  unsigned char *pubk, *p, *pp;
  int i, l, pubkl, tag, pl;
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
  byte *rsig;
  int rsigl, rsighl, rl;

  if (uid && !privkey)
    dodie("need -P option for non-root operation");
  expdays = atoi(expire);
  if (expdays <= 0 || expdays >= 10000)
    dodie("bad expire argument");
  slurp(pubkey, buf, sizeof(buf));
  pubk = unarmor_pubkey(buf, &pubkl);
  if (!pubk)
    dodie("could not parse pubkey armor");
  p = pubk;
  l = pubkl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 6)
    dodie("pubkey does not start with a pubkey paket");
  if (*pp != 4)
    dodie("pubkey is not type 4");
  pkcreat = pp[1] << 24 | pp[2] << 16 | pp[3] << 8 | pp[4];
  pk = pp;
  pkl = pl;
  calculatefingerprint(pk, pkl, fingerprint);

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 13)
    dodie("missing userid");
  userid = pp;
  useridl = pl;

  selfsigpkg = p;
  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 2)
    dodie("missing self-sig");
  if (pp[0] != 4)
    dodie("self-sig is not type 4");
  if (pp[1] != 0x13)
    dodie("self-sig is not class 0x13");
  if (pp[3] == 9 || pp[3] == 11)
    pp[3] = 8;	/* change sha384/224 to sha256 for now */
  if (pp[3] == 2)
    hashalgo = HASH_SHA1;
  else if (pp[3] == 8)
    hashalgo = HASH_SHA256;
  else if (pp[3] == 10)
    hashalgo = HASH_SHA512;
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
      algouser = doalloc(strlen(user) + strlen(hashname[hashalgo]) + 2);
      sprintf(algouser, "%s:%s", hashname[hashalgo], user);
    }
  if (pl < 6)
    dodie("self-sig is too short");
  ex = findsubpkg(pp + 4, pl - 4, 2);
  if (!ex)
    dodie("self-sig has no creation time");
  now = (u32)time((time_t)0);
  ex[0] = now >> 24;
  ex[1] = now >> 16;
  ex[2] = now >> 8;
  ex[3] = now;

  ex = findsubpkg(pp + 4, pl - 4, 9);
  if (!ex)
    dodie("self-sig does not expire");
  if (now < pkcreat)
    dodie("pubkey was created in the future");
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
    dodie("self-sig has bad hashed-length");
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
    dodie("self-sig has bad length");

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
  opensocket();
  rl = doreq(argc, args, rbuf, sizeof(rbuf), 1);
  if (rl < 0)
    exit(-rl);
  rsig = pkg2sig(rbuf + 4, rbuf[2] << 8 | rbuf[3], &rsigl);
  sigissuer = findsigissuer(rsig, rsigl);
  if (issuer && sigissuer && memcmp(issuer, sigissuer, 8))
    dodie("issuer does not match, did you forget -P?");
  if (memcmp(fingerprint + 12, sigissuer, 8))
    dodie("fingerprint does not match self sig");
  rsighl = findsigmpioffset(rsig, rsigl) - 2;	/* subtract 2 for hash bits */
  /*
   * pp: self-sig
   * pl: length of self-sig
   * hl: offset of left 16 bits of hash in v4 self-sig
   * rsig: new v3 sig
   * rsigl: length of new v3 sig
   * rsighl: offset of left 16 bits of hash in new v3 sig
   */
  newpubk = doalloc((selfsigpkg - pubk) + 4 + hl + (rsigl - rsighl) + l);
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
  free(pubk);
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
  struct x509 cb;
  char buf[8192];
  unsigned char rbuf[8192];
  char hashhex[1024];
  unsigned char *pubk;
  int pubkl;
  unsigned char *p, *pp;
  int i, l, tag, pl;
  time_t pkcreat, now, beg, exp;
  unsigned char *ex;
  unsigned char *userid;
  int useridl;
  const char *args[6];
  int argc;
  int rl;
  char *name, *nameend;
  char *email;
  byte *mpi[4];
  int mpil[4];
  int pubalgo;

  byte *rawssl;
  int rawssllen;
  HASH_CONTEXT ctx;
  byte *sigissuer, fingerprint[20];
  int sigl;
  byte *sig;

  if (uid && !privkey)
    dodie("need -P option for non-root operation");
  if (privkey)
    readprivkey();
  slurp(pubkey, buf, sizeof(buf));
  pubk = unarmor_pubkey(buf, &pubkl);
  if (!pubk)
    dodie("could not parse pubkey armor");
  p = pubk;
  l = pubkl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 6)
    dodie("pubkey does not start with a pubkey paket");
  if (pp[0] != 4)
    dodie("pubkey is not type 4");
  if (pp[5] == 1)
    pubalgo = PUB_RSA;
  else if (pp[5] == 17)
    pubalgo = PUB_DSA;
  else if (pp[5] == 22)
    pubalgo = PUB_EDDSA;
  else
    {
      fprintf(stderr, "unsupported pubkey algorithm %d\n", pp[5]);
      exit(1);
    }
  if (assertpubalgo == -1 && pubalgo != PUB_RSA)
    dodie("not a RSA pubkey");
  if (assertpubalgo >= 0 && assertpubalgo != pubalgo)
    {
      fprintf(stderr, "unexpected public key algorithm: wanted %s, got %s\n", pubalgoname[assertpubalgo], pubalgoname[pubalgo]);
      exit(1);
    }
  if (pubalgo == PUB_EDDSA)
    dodie("EdDSA certs are unsupported");
  calculatefingerprint(pp, pl, fingerprint);

  /* get creattion time */
  pkcreat = pp[1] << 24 | pp[2] << 16 | pp[3] << 8 | pp[4];

  /* get MPIs */
  if (pubalgo == PUB_RSA)
    setmpis(pp + 6, pl - 6, 2, mpi, mpil, 0);
  else if (pubalgo == PUB_DSA)
    setmpis(pp + 6, pl - 6, 4, mpi, mpil, 0);
  else if (pubalgo == PUB_EDDSA)
    setmpis(pp + 6, pl - 6, 2, mpi, mpil, 1);
  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 13)
    dodie("missing userid packet");
  userid = pp;
  useridl = pl;

  pp = nextpkg(&tag, &pl, &p, &l);
  if (tag != 2)
    dodie("missing self-sig");
  if (pp[0] != 4)
    dodie("self-sig is not type 4");
  if (pp[1] != 0x13)
    dodie("self-sig is not class 0x13");
  if (pl < 6)
    dodie("self-sig is too short");
  ex = findsubpkg(pp + 4, pl - 4, 2);
  if (!ex)
    dodie("self-sig has no creation time");
  beg = (ex[0] << 24 | ex[1] << 16 | ex[2] << 8 | ex[3]);
  now = (u32)time((time_t)0);
  if (beg > now)
    beg = now;
  ex = findsubpkg(pp + 4, pl - 4, 9);
  if (!ex)
    dodie("self-sig does not expire");
  exp = pkcreat + (ex[0] << 24 | ex[1] << 16 | ex[2] << 8 | ex[3]);
  if (exp < now)
    dodie("pubkey is already expired");
  
  /* split user id into name and email */
  name = doalloc(useridl + 1);
  strncpy(name, (char *)userid, useridl);
  name[useridl] = 0;
  if (!useridl || name[useridl - 1] != '>')
    dodie("userid does not end with email");
  name[useridl - 1] = 0;
  email = strrchr(name, '<');
  if (!email || email == name)
    dodie("userid does not end with email");
  nameend = email;
  *email++ = 0;
  while (nameend > name && (nameend[-1] == ' ' || nameend[-1] == '\t'))
    *--nameend = 0;

  /* limit to fixed sizes, see rfc 3280 */
  certsizelimit(name, 64);
  certsizelimit(email, 128);

  /* create tbscert */
  x509_init(&cb);
  x509_tbscert(&cb, name, email, beg, exp, pubalgo, mpi, mpil);
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
  opensocket();
  rl = doreq(argc, args, rbuf, sizeof(rbuf), 1);
  if (rl < 0)
    exit(-rl);

  sig = pkg2sig(rbuf + 4, rbuf[2] << 8 | rbuf[3], &sigl);
  sigissuer = findsigissuer(sig, sigl);
  if (sigissuer && memcmp(sigissuer, fingerprint + 12, 8))
    dodie("signature issuer does not match fingerprint");
  if (pubalgo != findsigpubalgo(sig, sigl))
    dodie("signature pubkey algorithm does not match pubkey");

  /* get signnature */
  assertpubalgo = pubalgo;
  rawssl = getrawopensslsig(sig, sigl, &rawssllen);
  if (!rawssl)
    exit(1);

  /* finish cert */
  x509_finishcert(&cb, pubalgo, rawssl, rawssllen);
  free(rawssl);

  /* print as PEM */
  printf("-----BEGIN CERTIFICATE-----\n");
  printr64(stdout, cb.buf, cb.len);
  printf("-----END CERTIFICATE-----\n");
  x509_free(&cb);
}

void
getpubkey()
{
  byte buf[8192], *bp;
  int outl;
  int ulen = strlen(user);
  if (privkey)
    dodie("pubkey fetching does not work with a private key");
  opensocket();
  /* we always use old style requests for the pubkey */
  if (ulen + 6 + 4 + 1 + (hashalgo == HASH_SHA1 ? 0 : strlen(hashname[hashalgo]) + 1) > sizeof(buf))
    dodie("packet too big");
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
  strcpy((char *)bp, "PUBKEY");
  bp += 6;
  buf[3] = bp - (buf + 4 + ulen);
  outl = doreq_old(buf, (int)(bp - buf), sizeof(buf));
  if (outl < 0)
    exit(-outl);
  fwrite(buf, 1, outl, stdout);
}

void
ping()
{
  byte buf[256];
  int r;
  memset(buf, 0, 4);
  opensocket();
  r = doreq_old(buf, 4, sizeof(buf));
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
    dodie_errno(conf);
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
	  free(user);
	  user = strdup(bp);
	  continue;
	}
      if (!strcmp(buf, "server"))
	{
	  free(host);
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
	  else if (!strcasecmp(bp, "sha512"))
	    hashalgo = HASH_SHA512;
	  else
	    dodie("sign.conf: unsupported hash argument");
	}
      if (!strcmp(buf, "allow-unprivileged-ports"))
	{
	  if (!strcmp(bp, "true"))
	    allow_unprivileged_ports = 1;
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

void
readcert(struct x509 *cert, char *certfile)
{
  char buf[32768];

  slurp(certfile, buf, sizeof(buf));
  if (!x509_addpem(cert, buf, "CERTIFICATE"))
    {
      fprintf(stderr, "%s: not a certificate\n", certfile);
      exit(1);
    }
}

void
readothercerts(struct x509 *othercerts, char *certfile)
{
  char buf[65536];
  int l = slurp(certfile, buf, sizeof(buf));
  if (slurp(certfile, buf, sizeof(buf)) == 0)
    return;
  if (*buf != 0x30)
    {
      fprintf(stderr, "%s: not DER encoded certificates\n", certfile);
      exit(1);
    }
  x509_insert(othercerts, 0, (unsigned char *)buf, l);
}

void
hashfile(char *filename, int isfilter)
{
  int l, i, fd;
  char hashhex[1024];
  byte *p;
  unsigned char buf[4096];

  HASH_CONTEXT ctx;
  if (isfilter)
    fd = 0;
  else if ((fd = open(filename, O_RDONLY)) == -1)
    dodie_errno(filename);
  hash_init(&ctx);
  while ((l = read(fd, buf, sizeof(buf))) > 0)
    hash_write(&ctx, buf, l);
  hash_final(&ctx);
  p = hash_read(&ctx);
  for (i = 0; i < hashlen[hashalgo]; i++)
    sprintf(hashhex + i * 2, "%02x", p[i]);
  printf("%s\n", hashhex);
  if (!isfilter)
    close(fd);
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
  x509_init(&cert);
  x509_init(&othercerts);

  if (argc > 2 && !strcmp(argv[1], "--test-sign"))
    {
      test_sign = argv[2];
      argc -= 2;
      argv += 2;
      conf = getenv("SIGN_CONF");
      allowuser = 1;
    }
  if (argc > 2 && !strcmp(argv[1], "--config"))
    {
      if (uid && !test_sign)
	dodie("sign: only root may use --config");
      conf = argv[2];
      argc -= 2;
      argv += 2;
    }
  read_sign_conf(conf ? conf : "/etc/sign.conf");

  if (uid)
    {
      if (!allowuser)
	dodie("sign: permission denied");
      if (seteuid(uid))
	dodie_errno("seteuid");
    }
  if (argc == 2 && !strcmp(argv[1], "-t"))
    {
      ping();
      exit(0);
    }
  while (argc > 1)
    {
      const char *opt = argv[1];
      if (opt[0] != '-')
	break;
      argc--;
      argv++;
      if (!strcmp(opt, "--help"))
        {
          usage();
          exit(0);
        }
      else if (argc > 1 && !strcmp(opt, "-u"))
	{
	  free(user);
	  user = strdup(argv[1]);
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(opt, "-h"))
	{
	  if (!strcasecmp(argv[1], "sha1"))
	    hashalgo = HASH_SHA1;
	  else if (!strcasecmp(argv[1], "sha256"))
	    hashalgo = HASH_SHA256;
	  else if (!strcasecmp(argv[1], "sha512"))
	    hashalgo = HASH_SHA512;
	  else
	    {
	      fprintf(stderr, "sign: unknown hash algorithm '%s'\n", argv[1]);
	      exit(1);
	    }
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(opt, "-A"))
	{
	  if (!strcasecmp(argv[1], "dsa"))
	    assertpubalgo = PUB_DSA;
	  else if (!strcasecmp(argv[1], "rsa"))
	    assertpubalgo = PUB_RSA;
	  else if (!strcasecmp(argv[1], "eddsa"))
	    assertpubalgo = PUB_EDDSA;
	  else
	    {
	      fprintf(stderr, "sign: unknown pubkey algorithm '%s'\n", argv[1]);
	      exit(1);
	    }
	  argc--;
	  argv++;
	}
      else if (!strcmp(opt, "-c"))
	mode = MODE_CLEARSIGN;
      else if (!strcmp(opt, "-d"))
	mode = MODE_DETACHEDSIGN;
      else if (!strcmp(opt, "-D"))
	mode = MODE_RAWDETACHEDSIGN;
      else if (!strcmp(opt, "-O"))
	mode = MODE_RAWOPENSSLSIGN;
      else if (!strcmp(opt, "-r"))
	mode = MODE_RPMSIGN;
      else if (!strcmp(opt, "-a") || !strcmp(opt, "--appimage"))
	mode = MODE_APPIMAGESIGN;
      else if (!strcmp(opt, "-v"))
	verbose++;
      else if (!strcmp(opt, "--noheaderonly"))
	noheaderonly = 1;
      else if (!strcmp(opt, "-k"))
	mode = MODE_KEYID;
      else if (!strcmp(opt, "-p"))
	mode = MODE_PUBKEY;
      else if (!strcmp(opt, "-g"))
	mode = MODE_KEYGEN;
      else if (!strcmp(opt, "-x"))
	mode = MODE_KEYEXTEND;
      else if (!strcmp(opt, "-C"))
	mode = MODE_CREATECERT;
      else if (!strcmp(opt, "--hashfile"))
	mode = MODE_HASHFILE;
      else if (argc > 1 && !strcmp(opt, "-S"))
	{
	  chksumfile = argv[1];
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(opt, "-T"))
	{
	  timearg = argv[1];
	  argc--;
	  argv++;
	  if (!*timearg || ((*timearg < '0' || *timearg > '9') && strcmp(timearg, "mtime") && strcmp(timearg, "buildtime")))
	    {
	      fprintf(stderr, "illegal time argument: %s\n", timearg);
	      exit(1);
	    }
	}
      else if (argc > 1 && !strcmp(opt, "-P"))
        {
	  privkey = argv[1];
	  argc--;
	  argv++;
        }
      else if (!strcmp(opt, "--pkcs1pss"))
	pkcs1pss = 1;
      else if (!strcmp(opt, "-4"))
	dov4sig = 1;
      else if (argc > 1 && !strcmp(opt, "--cert"))
	{
	  readcert(&cert, argv[1]);
	  argc--;
	  argv++;
	}
      else if (argc > 1 && !strcmp(opt, "--othercerts"))
	{
	  readothercerts(&othercerts, argv[1]);
	  argc--;
	  argv++;
	}
      else if (!strcmp(opt, "--appx"))
	mode = MODE_APPXSIGN;
      else if (!strcmp(opt, "--appxdetached"))
	{
	  mode = MODE_APPXSIGN;
	  appxdetached = 1;
	}
      else if (!strcmp(opt, "--cmssign"))
	mode = MODE_CMSSIGN;
      else if (!strcmp(opt, "--pesign"))
	mode = MODE_PESIGN;
      else if (!strcmp(opt, "--kosign"))
	mode = MODE_KOSIGN;
      else if (!strcmp(opt, "--cms-nocerts"))
	cms_flags |= X509_PKCS7_NO_CERTS;
      else if (!strcmp(opt, "--cms-keyid"))
	cms_flags |= X509_PKCS7_USE_KEYID;
      else if (!strcmp(opt, "--"))
	break;
      else
	{
	  usage();
	  exit(1);
	}
    }
  if (mode == MODE_CREATECERT)
    hashalgo = HASH_SHA256;	/* always sign certs with sha256 */
  if (mode == MODE_APPXSIGN)
    hashalgo = HASH_SHA256;	/* always sign appx with sha256 */
  if (mode == MODE_PESIGN)
    hashalgo = HASH_SHA256;	/* always sign PE with sha256 */
  if (hashalgo == HASH_SHA1)
    algouser = user;
  else
    {
      algouser = doalloc(strlen(user) + strlen(hashname[hashalgo]) + 2);
      sprintf(algouser, "%s:%s", hashname[hashalgo], user);
    }
  if (pkcs1pss && mode != MODE_RAWOPENSSLSIGN)
    dodie("can only generate a pkcs1pss signature in openssl mode");
  if (mode == MODE_PUBKEY)
    {
      if (argc != 1)
	dodie("usage: sign -p [-u user]");
      getpubkey();
      exit(0);
    }
  if (mode == MODE_KEYGEN)
    {
      if (argc != 5)
	dodie("usage: sign -g <type> <expire> <name> <email>");
      keygen(argv[1], argv[2], argv[3], argv[4]);
      exit(0);
    }
  if (mode == MODE_KEYEXTEND)
    {
      if (argc != 3)
        dodie("usage: sign -x <expire> <pubkey>");
      keyextend(argv[1], argv[2]);
      exit(0);
    }
  if (mode == MODE_CREATECERT)
    {
      if (argc != 2)
	dodie("usage: sign -C <pubkey>");
      initrandom();
      createcert(argv[1]);
      exit(0);
    }
  if (mode == MODE_KEYID)
    {
      if (argc != 1)
	dodie("usage: sign -k [-u user]");
      dov4sig = 0;	/* no need for the extra work */
      sign("<stdin>", 1, mode);
      exit(0);
    }
  if (mode == MODE_HASHFILE)
    {
      if (argc == 1)
        hashfile("<stdin>", 1);
      else if (argc == 2)
        hashfile(argv[1], 0);
      else
	dodie("usage: sign --hashfile [-h algo] [file]");
      exit(0);
    }
  if (mode == MODE_RAWOPENSSLSIGN)
    dov4sig = 0;	/* no need for the extra work */
  if (privkey && access(privkey, R_OK))
    dodie_errno(privkey);

  if (dov4sig)
    pubalgoprobe = probe_pubalgo();

  if (chksumfile)
    {
      if (strcmp(chksumfile, "-"))
	chksumfilefd = open(chksumfile, O_WRONLY|O_CREAT|O_APPEND, 0666);
      else
	chksumfilefd = 1;
      if (chksumfilefd < 0)
	dodie_errno(chksumfile); 
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
        dodie_errno("chksum file close");
    }
  x509_free(&cert);
  x509_free(&othercerts);
  exit(0);
}

