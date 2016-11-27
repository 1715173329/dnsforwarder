#include "mmgr.h"
#include "udpm.h"
#include "stringchunk.h"

static Array Modules;
static StringChunk  Distributor;

static int Udp_Init(ConfigFileInfo *ConfigInfo)
{
    UdpM *m;

    while( TRUE )
    {

    }
}

int MMgr_Init(ConfigFileInfo *ConfigInfo)
{
    if( StringChunk_Init(&Distributor, NULL) != 0 )
    {
        return -10;
    }

    /*  */
}
