#include <utils.h>

char* pt(unsigned char* md, size_t size)
{
  size_t i;
  char* buf = (char*)calloc(size*4, sizeof (char));

  for (i = 0; i < size; i++)
    sprintf(&(buf[i * 2]), "%02x", md[i]);

  return (buf);
}
