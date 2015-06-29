#include <stdint.h>

int strlen(const char* s)
{
  int i = 0;
  while(s[i])
    i++;
  return i;
}

int strnlen(const char* s, int n)
{
  int i = 0;
  while(i < n && s[i])
    i++;
  return i;
}

char* strcpy(char* d, const char* s)
{
  int i = 0;
  while(d[i] = s[i])
    i++;

  return d;
}

char* strncpy(char* d, const char* s, int n)
{
  int i = 0;
  while(i < n && (d[i] = s[i]))
    i++;
  return d;
}

int strcmp(const char* s0, const char* s1)
{
  int i = 0;
  while(s0[i] && s0[i] == s1[i])
    i++;
  return (int)(s0[i]-s1[i]);
}

int strncmp(const char* s0, const char* s1, int n)
{
  int i = 0;
  while(i < n && s0[i] && s0[i] == s1[i])
    i++;
  return n ? (int)(s0[i]-s1[i]) : 0;
}

static inline void *
memset16(uint32_t *_v, uint32_t c, unsigned n)
{
  uint32_t *start, *end;
  uint32_t *v;

  start = _v;
  end = _v + n/sizeof(uint32_t);
  v = _v;
  c = c | c<<8 | c<<16 | c<<24;

  if(n >= 64 && ((intptr_t)v) % 8 == 0)
  {
    uint64_t* v64 = (uint64_t*)v;
    uint64_t c64 = c | ((uint64_t)c)<<32;
    while(v64 < (uint64_t*)end-7)
    {
      v64[3] = v64[2] = v64[1] = v64[0] = c64;
      v64[7] = v64[6] = v64[5] = v64[4] = c64;
      v64 += 8;
    }
    v = (uint32_t*)v64;
  }

  while(v < end)
  {
    v[3] = v[2] = v[1] = v[0] = c;
    v += 4;
  }

  return start;
}

void *
memset(void *v, int c, unsigned _n)
{
  char *p;
  unsigned n0;
  unsigned n = _n;

  if (n == 0)
    return 0;

  p = v;

  while (n > 0 && ((uintptr_t)p & 7))
  {
    *p++ = c;
    n--;
  }

  if(n >= 16 && ((uintptr_t)p & 3) == 0)
  {
    n0 = (n/16)*16;
    memset16((uint32_t*)p,c,n0);
    n -= n0;
    p += n0;
  }

  while (n > 0)
  {
    *p++ = c;
    n--;
  }

  return v;
}

void* memcpy(void* d, const void* s, int n)
{
  int i;
  for(i = 0; i < n; i++)
    ((char*)d)[i] = ((char*)s)[i];
  return d;
}

char* strcat(char* d, const char* s)
{
  strcpy(d+strlen(d),s);
  return d;
}

char* strncat(char* d, const char* s, int n)
{
  int len = strlen(d), i = 0;
  while(i < n && (d[len+i] = s[i]))
    i++;
  if(i == n)
    d[len+i-1] = '\0';
  return d;
}
