
static inline unsigned int
getle2(const unsigned char *b)
{
  return b[0] | b[1] << 8;
}

static inline unsigned int
getle4(const unsigned char *b)
{
  return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
}

static inline void
setle2(unsigned char *b, unsigned int v)
{
  b[0] = v & 255;
  b[1] = (v >> 8) & 255;
}

static inline void
setle4(unsigned char *b, unsigned int v)
{
  b[0] = v & 255;
  b[1] = (v >> 8) & 255;
  b[2] = (v >> 16) & 255;
  b[3] = (v >> 24) & 255;
}


static inline unsigned int
getbe4(const unsigned char *b)
{
  return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
}

static inline void
setbe4(unsigned char *b, unsigned int x)
{
  b[0] = x >> 24;
  b[1] = x >> 16;
  b[2] = x >> 8;
  b[3] = x;
}

