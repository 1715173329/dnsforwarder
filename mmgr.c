#include "mmgr.h"
#include "udpm.h"
#include "stringchunk.h"
#include "utils.h"
#include "filter.h"

typedef int (*SendFunc)(void *Module,
                        IHeader *h, /* Entity followed */
                        int FullLength
                        );

typedef struct _ModuleInterface {
    union {
        UdpM    Udp;
    } ModuleUnion;

    SendFunc    Send;

    const char *ModuleName;

} ModuleInterface;

static StableBuffer Modules; /* Storing ModuleInterfaces */
static Array        ModuleArray; /* ModuleInterfaces' references */
static StringChunk  Distributor; /* Domain-to-ModuleInterface mapping */

static int MappingAModule(ModuleInterface *m, const char *Domains)
{
    ModuleInterface *Added;
    StringList  DomainList;
    StringListIterator  i;

    const char *OneDomain;

    Added = Modules.Add(&Modules, m, sizeof(ModuleInterface));
    if( Added == NULL )
    {
        return -30;
    }

    Array_PushBack(&ModuleArray, &Added, NULL);

    if( StringList_Init(&DomainList, Domains, ",") != 0 )
    {
        return -38;
    }

    DomainList.TrimAll(&DomainList);

    if( StringListIterator_Init(&i, &DomainList) != 0 )
    {
        return -46;
    }

    while( (OneDomain = i.Next(&i)) != NULL )
    {
        StringChunk_Add_Domain(&Distributor,
                               OneDomain,
                               &Added,
                               sizeof(ModuleInterface *)
                               );
    }

    DomainList.Free(&DomainList);

    return 0;
}

static int Udp_Init(ConfigFileInfo *ConfigInfo)
{
    ModuleInterface NewM;

    StringList  *UDPGroups;
    StringListIterator  i;

    UDPGroups = ConfigGetStringList(ConfigInfo, "UDPGroup");
    if( UDPGroups == NULL )
    {
        return 0;
    }

    if( StringListIterator_Init(&i, UDPGroups) != 0 )
    {
        return -33;
    }

    NewM.ModuleName = "UDP";

    while( TRUE )
    {
        const char *Services;
        const char *Domains;
        const char *Parallel;
        char ParallelOnOff[8];
        BOOL ParallelQuery;

        Services = i.Next(&i);
        Domains = i.Next(&i);
        Parallel = i.Next(&i);

        if( Services == NULL || Domains == NULL || Parallel == NULL )
        {
            break;
        }

        strncpy(ParallelOnOff, Parallel, sizeof(ParallelOnOff));
        ParallelOnOff[sizeof(ParallelOnOff) - 1] = '\0';
        StrToLower(ParallelOnOff);

        if( strcmp(ParallelOnOff, "on") == 0 )
        {
            ParallelQuery = TRUE;
        } else {
            ParallelQuery = FALSE;
        }

        if( UdpM_Init(&(NewM.ModuleUnion.Udp), Services, ParallelQuery) != 0 )
        {
            continue;
        }

        NewM.Send = (SendFunc)(NewM.ModuleUnion.Udp.Send);

        if( MappingAModule(&NewM, Domains) != 0 )
        {
            /** TODO: Show error */
        }
    }

    UDPGroups->Free(UDPGroups);
    return 0;
}

int MMgr_Init(ConfigFileInfo *ConfigInfo)
{
    BOOL ret = FALSE;

    if( StringChunk_Init(&Distributor, NULL) != 0 )
    {
        return -10;
    }

    if( StableBuffer_Init(&Modules) != 0 )
    {
        return -27;
    }

    if( Array_Init(&ModuleArray,
                   sizeof(ModuleInterface *),
                   0,
                   FALSE,
                   NULL
                   )
       != 0 )
    {
        return -98;
    }

    if( Filter_Init(ConfigInfo) != 0 )
    {
        return -157;
    }

    ret |= (Udp_Init(ConfigInfo) == 0);

    return !ret;
}

int MMgr_Send(IHeader *h, int FullLength)
{
    ModuleInterface *i;

    if( Filter_Out(h) )
    {
        /** TODO: Show filtered message */
        return -170;
    }

    if( StringChunk_Domain_Match(&Distributor,
                                 h->Domain,
                                 &(h->HashValue),
                                 (void **)&i
                                 )
       )
    {
    } else {
        i = Array_GetBySubscript(&ModuleArray,
                                 FullLength % Array_GetUsed(&ModuleArray)
                                 );
    }

    if( i == NULL )
    {
        return -190;
    }

    return i->Send(&(i->ModuleUnion), h, FullLength);
}
