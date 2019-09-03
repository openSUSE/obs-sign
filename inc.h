#include <stdio.h>
#include <sys/types.h>

typedef unsigned int u32;
typedef unsigned char byte;

#define HASH_SHA1       0
#define HASH_SHA256     1

#define PUB_DSA         0
#define PUB_RSA         1

/* sign.c */
extern int hashalgo;

/* hash.c */
typedef struct {
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buf[64];
    int  count;
} SHA1_CONTEXT;

typedef struct {
    u32  h0,h1,h2,h3,h4,h5,h6,h7;
    u32  nblocks;
    byte buf[64];
    int  count;
} SHA256_CONTEXT;

typedef struct MD5Context {
        u32 buf[4];
        u32 bits[2];
        byte in[64];
} MD5_CTX;

typedef union {
  SHA1_CONTEXT sha1;
  SHA256_CONTEXT sha256;
} HASH_CONTEXT;

void sha1_init(SHA1_CONTEXT *hd);
void sha1_write(SHA1_CONTEXT *hd, const byte *inbuf, size_t inlen);
void sha1_final(SHA1_CONTEXT *hd);
byte *sha1_read(SHA1_CONTEXT *hd);

void sha256_init(SHA256_CONTEXT *hd);
void sha256_write(SHA256_CONTEXT *hd, const byte *inbuf, size_t inlen);
void sha256_final(SHA256_CONTEXT *hd);
byte *sha256_read(SHA256_CONTEXT *hd);

void md5_init(struct MD5Context *ctx);
void md5_write(struct MD5Context *ctx, byte const *buf, u32 len);
void md5_final(byte *digest, struct MD5Context *ctx);

void hash_init(HASH_CONTEXT *c);
void hash_write(HASH_CONTEXT *c, const unsigned char *b, size_t l);
void hash_final(HASH_CONTEXT *c);
unsigned char *hash_read(HASH_CONTEXT *c);

/* base64.c */
void printr64(FILE *f, const byte *str, int len);
char *r64dec1(char *p, unsigned int *vp, int *eofp);
char *r64dec(char *p, unsigned char **bpp);

/* pgp.c */
void write_armored_pubkey(FILE *fp, const byte *pubkey, int length);
void write_armored_signature(FILE *fp, const byte *signature, int length);
char *get_armored_signature(const byte *signature, int length);
unsigned char *unarmor_pubkey(char *pubkey, int *pktlp);

unsigned char *genv4sigtrail(int clearsign, int pubalgo, int hashalgo, u32 signtime, int *v4sigtraillen);
int v3tov4(unsigned char *v4sigtrail, unsigned char *v3sig, int v3siglen, int tail, int left);
unsigned char *nextpkg(int *tagp, int *pkgl, unsigned char **pp, int *ppl);
unsigned char *findsubpkg(unsigned char *q, int l, int type);
unsigned char *addpkg(unsigned char *to, unsigned char *p, int l, int tag, int newformat);
byte *pkg2sig(byte *pk, int pkl, int *siglp);
void calculatefingerprint(byte *pub, int publ, byte *fingerprintp);
byte *findsigissuer(byte *sig, int sigl);
int findsigmpioffset(byte *sig, int sigl);
int findsigpubalgo(byte *pk, int pkl);

/* x509.c */
struct x509 {
  byte *buf;
  int len; 
  int alen;	/* allocated length */
};

static inline void x509_init(struct x509 *cb) { memset(cb, 0, sizeof(*cb)); }
static inline void x509_free(struct x509 *cb) { free(cb->buf); }
void x509_tbscert(struct x509 *cb, const char *cn, const char *email, time_t start, time_t end, byte *p, int pl, byte *e, int el);
void x509_finishcert(struct x509 *cb, byte *sig, int sigl);
byte *getrawopensslsig(byte *sig, int sigl, int *lenp);
void certsizelimit(char *s, int l);

/* rpm.c */
struct rpmdata {
  byte rpmlead[96];
  byte rpmsighead[16];
  int rpmsigcnt;
  int rpmsigdlen;
  int rpmsigsize;
  byte *rpmsig;         /* signature data (with room for two new signatures) */

  u32 rpmdataoff;
  u32 hdrin_size;
  byte *hdrin_md5;      /* points into rpmsig */
  int gotsha1;          /* did we see a RPMSIGTAG_SHA1 tag? */

  u32 buildtime;
  byte rpmmd5sum[16];   /* md5sum over header+payload */

  byte chksum_leadmd5[16];
  byte chksum_md5[16];
  byte chksum_sha1[20];
  byte chksum_sha256[32];
};

int rpm_insertsig(struct rpmdata *rd, int hdronly, byte *newsig, int newsiglen);
int rpm_read(struct rpmdata *rd, int fd, char *filename, HASH_CONTEXT *ctx, HASH_CONTEXT *hctx, int getbuildtime);
int rpm_write(struct rpmdata *rd, int foutfd, int fd, int chksumfilefd);
void rpm_writechecksums(struct rpmdata *rd, int chksumfilefd);

/* appimage.c */
void appimage_write_signature(char *filename, byte *signature, int length);

/* sock.c */
void opensocket(void);
void closesocket(void);
int doreq_old(byte *buf, int inbufl, int bufl);
int doreq(int argc, const char **argv, byte *buf, int bufl, int nret);

/* clearsign.c */
int clearsign(int fd, char *filename, char *outfilename, HASH_CONTEXT *ctx, const char *hname, int isfilter, int force, FILE **foutp);

