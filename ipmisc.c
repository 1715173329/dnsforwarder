#include "ipmisc.h"

static int IPMisc_AddBlockFromString(IPMisc *m, const char *Ip)
{
    return IpChunk_AddAnyFromString(&(m->c),
                                    Ip,
                                    (int)IP_MISC_TYPE_BLOCK,
                                    NULL,
                                    0
                                    );
}

int IPMisc_Init(IPMisc *m)
{
    if( IpChunk_Init(&(m->c)) != 0 )
    {
        return -1;
    }

    return 0;
}
