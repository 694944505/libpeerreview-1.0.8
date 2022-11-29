#include <sys/time.h>

#include "peerreview.h"

SimplePRNG::SimplePRNG()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srand48_r(tv.tv_usec ^ tv.tv_sec, &seed);
}

int SimplePRNG::getRandom(int range)
{
  if (range < 1)
    return 0;

  long int result;
  lrand48_r(&seed, &result);

  return (((unsigned int)result) % range);
}

int SimplePRNG::storeCheckpoint(unsigned char *buffer, unsigned int maxlen)
{ 
  if (maxlen < sizeof(seed))
    return 0;
    
  memcpy(buffer, &seed, sizeof(seed));
  return sizeof(seed);
}

bool SimplePRNG::loadCheckpoint(unsigned char *buffer, unsigned int *ptr, unsigned int maxlen)
{
  if ((maxlen - (*ptr)) < sizeof(seed))
    return false;
    
  memcpy(&seed, &buffer[*ptr], sizeof(seed));
  *ptr += sizeof(seed);
  
  return true;
}
