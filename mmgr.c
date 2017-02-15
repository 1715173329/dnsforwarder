#include <string.h>
#include "mmgr.h"
#include "stringchunk.h"
#include "utils.h"
#include "filter.h"
#include "hosts.h"
#include "dnscache.h"
#include "logs.h"
#include "ipmisc.h"
#include "readline.h"

typedef int (*SendFunc)(void *Module,
                        IHeader *h, /* Entity followed */
                        int BufferLength
                        );

typedef struct _ModuleInterface {
    union {
        UdpM    Udp;
        TcpM    Tcp;
    } ModuleUnion;

    SendFunc    Send;

    const char *ModuleName;

} ModuleInterface;

static StableBuffer Modules; /* Storing ModuleInterfaces */
static Array        ModuleArray; /* ModuleInterfaces' references */
static StringChunk  Distributor; /* Domain-to-ModuleInterface mapping */

static int MappingAModule(ModuleInterface *Stored, const char *Domains)
{
    StringList  DomainList;
    StringListIterator  i;

    const char *OneDomain;

    if( StringList_Init(&DomainList, Domains, ",") != 0 )
    {
        return -38;
    }

    DomainList.TrimAll(&DomainList, "\t .");
    DomainList.LowercaseAll(&DomainList);

    if( StringListIterator_Init(&i, &DomainList) != 0 )
    {
        return -46;
    }

    while( (OneDomain = i.Next(&i)) != NULL )
    {
        StringChunk_Add_Domain(&Distributor,
                               OneDomain,
                               &Stored,
                               sizeof(ModuleInterface *)
                               );
    }

    DomainList.Free(&DomainList);

    return 0;
}

static ModuleInterface *StoreAModule(void)
{
    ModuleInterface *Added;

    Added = Modules.Add(&Modules, NULL, sizeof(ModuleInterface), TRUE);
    if( Added == NULL )
    {
        return NULL;
    }

    if( Array_PushBack(&ModuleArray, &Added, NULL) < 0 )
    {
        return NULL;
    }

    Added->ModuleName = "Unknown";

    return Added;
}

static int Udp_Init(StringListIterator  *i)
{
    ModuleInterface *NewM;

    const char *Services;
    const char *Domains;
    const char *Parallel;
    char ParallelOnOff[8];
    BOOL ParallelQuery;

    /* Initializing parameters */
    Services = i->Next(i);
    Domains = i->Next(i);
    Parallel = i->Next(i);

    if( Services == NULL || Domains == NULL || Parallel == NULL )
    {
        return -103;
    }

    NewM = StoreAModule();
    if( NewM == NULL )
    {
        return -101;
    }

    NewM->ModuleName = "UDP";

    strncpy(ParallelOnOff, Parallel, sizeof(ParallelOnOff));
    ParallelOnOff[sizeof(ParallelOnOff) - 1] = '\0';
    StrToLower(ParallelOnOff);

    if( strcmp(ParallelOnOff, "on") == 0 )
    {
        ParallelQuery = TRUE;
    } else {
        ParallelQuery = FALSE;
    }

    /* Initializing module */
    if( UdpM_Init(&(NewM->ModuleUnion.Udp), Services, ParallelQuery) != 0 )
    {
        return -128;
    }

    NewM->Send = (SendFunc)(NewM->ModuleUnion.Udp.Send);

    if( MappingAModule(NewM, Domains) != 0 )
    {
        ERRORMSG("Mapping UDP module for %s failed.\n", Domains);
    }

    return 0;
}

static int Tcp_Init(StringListIterator  *i)
{
    ModuleInterface *NewM;

    const char *Services;
    const char *Domains;
    const char *Proxies;
    char ProxyString[8];

    /* Initializing parameters */
    Services = i->Next(i);
    Domains = i->Next(i);
    Proxies = i->Next(i);

    if( Services == NULL || Domains == NULL || Proxies == NULL )
    {
        return -157;
    }

    NewM = StoreAModule();
    if( NewM == NULL )
    {
        return -192;
    }

    NewM->ModuleName = "TCP";

    strncpy(ProxyString, Proxies, sizeof(ProxyString));
    ProxyString[sizeof(ProxyString) - 1] = '\0';
    StrToLower(ProxyString);

    if( strcmp(ProxyString, "no") == 0 )
    {
        Proxies = NULL;
    }

    /* Initializing module */
    if( TcpM_Init(&(NewM->ModuleUnion.Tcp), Services, Proxies) != 0 )
    {
        return -180;
    }

    NewM->Send = (SendFunc)(NewM->ModuleUnion.Tcp.Send);

    if( MappingAModule(NewM, Domains) != 0 )
    {
        ERRORMSG("Mapping TCP module for %s failed.\n", Domains);
    }

    return 0;
}

/*
# UDP
PROTOCOL UDP
SERVER 1.2.4.8
PARALLEL ON

example.com

*/
static int Modules_InitFromFile(StringListIterator  *i)
{
    #define MAX_PATH_BUFFER     256
/*
    const char *FileOri;
    char File[MAX_PATH_BUFFER];
    FILE *fp;

    ReadLineStatus  Status;
    char Buffer[1024];

    const char *Protocol = NULL;

    FileOri = i->Next(i);

    if( FileOri == NULL )
    {
        return -201;
    }

    strncpy(File, FileOri, sizeof(File));
    File[sizeof(File) - 1] = '\0';

    ReplaceStr(File, "\"", "");

    fp = fopen(File, "r");
    if( fp == NULL )
    {
        ERRORMSG("Cannot open file %s.\n", File);
        return -208;
    }

    do {
        Status = ReadLine(fp, Buffer, sizeof(Buffer));

        if( Status == READ_TRUNCATED )
        {
            Status = ReadLine_GoToNextLine(fp);
        }

        StrToLower(Buffer);
        if( strncmp(Buffer, "protocol", sizeof("protocol") - 1) == 0 )
        {
            Protocol = GoToNextNonSpace(strpbrk(Buffer, "\t "));

            if( Protocol != NULL )
            {
                rewind(fp);
                break;
            }
        }

    } while( Status != READ_FAILED_OR_END );

    if( Protocol == NULL )
    {
        INFO("No protocol specified, file %s.\n", File);
        return -260;
    }

    if( strcmp(Protocol, "udp") == 0 )
    {

    } else if( strcmp(Protocol, "tcp") == 0 )
    {

    } else {
        INFO("Unknown protocol %s, file %s.\n", Protocol, File);
        return -271;
    }
*/
    return 0;
}

static int Modules_Init(ConfigFileInfo *ConfigInfo)
{
    StringList  *ServerGroups;
    StringListIterator  i;

    const char *Type;

    ServerGroups = ConfigGetStringList(ConfigInfo, "ServerGroup");
    if( ServerGroups == NULL )
    {
        ERRORMSG("Please set at least one server group.\n");
        return -202;
    }

    if( StringListIterator_Init(&i, ServerGroups) != 0 )
    {
        return -207;
    }

    while( (Type = i.Next(&i)) != NULL )
    {
        if( strcmp(Type, "UDP") == 0 )
        {
            if( Udp_Init(&i) != 0 )
            {
                ERRORMSG("Initializing UDPGroups failed.\n");
                return -218;
            }
        } else if( strcmp(Type, "TCP") == 0 )
        {
            if( Tcp_Init(&i) != 0 )
            {
                ERRORMSG("Initializing TCPGroups failed.\n");
                return -226;
            }
        } else if( strcmp(Type, "FILE") == 0 )
        {
            if( Modules_InitFromFile(&i) != 0 )
            {
                ERRORMSG("Initializing group files failed.\n");
                return -318;
            }
        } else {
            ERRORMSG("Initializing server groups failed, near %s.\n", Type);
            return -230;
        }
    }

    INFO("Server groups initialized.\n", Type);
    return 0;
}

int MMgr_Init(ConfigFileInfo *ConfigInfo)
{
    if( Filter_Init(ConfigInfo) != 0 )
    {
        return -159;
    }

    /* Hosts & Cache */
    if( Hosts_Init(ConfigInfo) != 0 )
    {
        return -165;
    }

    if( DNSCache_Init(ConfigInfo) != 0 )
    {
        return -164;
    }

    if( IpMiscSingleton_Init(ConfigInfo) != 0 )
    {
        return -176;
    }

    /* Ordinary modeles */
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

    return Modules_Init(ConfigInfo);
}

int MMgr_Send(IHeader *h, int BufferLength)
{
    ModuleInterface **i;
    ModuleInterface *TheModule;

    /* Determine whether to discard the query */
    if( Filter_Out(h) )
    {
        return 0;
    }

    /* Hosts & Cache */
    if( Hosts_Get(h, BufferLength) == 0 )
    {
        return 0;
    }

    if( DNSCache_FetchFromCache(h, BufferLength) == 0 )
    {
        return 0;
    }

    /* Ordinary modeles */
    if( StringChunk_Domain_Match(&Distributor,
                                 h->Domain,
                                 &(h->HashValue),
                                 (void **)&i
                                 )
       )
    {
    } else if( Array_GetUsed(&ModuleArray) > 0 ){
        i = Array_GetBySubscript(&ModuleArray,
                                 h->EntityLength % Array_GetUsed(&ModuleArray)
                                 );
    } else {
        i = NULL;
    }

    if( i == NULL || *i == NULL )
    {
        return -190;
    }

    TheModule = *i;

    return TheModule->Send(&(TheModule->ModuleUnion), h, BufferLength);
}
