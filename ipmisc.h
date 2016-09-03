#ifndef IPMISC_H_INCLUDED
#define IPMISC_H_INCLUDED

#include "ipchunk.h"

typedef enum _MiscType {
    IP_MISC_TYPE_UNKNOWN = 0,
    IP_MISC_TYPE_BLOCK = 1,
    IP_MISC_TYPE_SUBSTITUTE = 2,
} MiscType;

#define IP_MISC_ACTION_NOTHING 0
#define IP_MISC_ACTION_BLOCK (-1)

typedef struct _IPMisc IPMisc;

struct _IPMisc{
    /* private */
    IpChunk c;

};

#endif // IPMISC_H_INCLUDED
