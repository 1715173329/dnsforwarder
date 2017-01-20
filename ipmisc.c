#include <string.h>
#include "ipmisc.h"
#include "utils.h"

static int IPMisc_AddBlockFromString(IPMisc *m, const char *Ip)
{
    return IpChunk_AddAnyFromString(&(m->c),
                                    Ip,
                                    (int)IP_MISC_TYPE_BLOCK,
                                    NULL,
                                    0
                                    );
}

static int IPMisc_AddSubstituteFromString(IPMisc *m,
                                          const char *Ip,
                                          const char *Substituter
                                          )
{
    if( strchr(Ip, ':') != NULL )
    {   /* IPv6 */
        char	IpSubstituter[16];

        IPv6AddressToNum(Substituter, IpSubstituter);

        return IpChunk_Add6FromString(&(m->c),
                                      Ip,
                                      (int)IP_MISC_TYPE_SUBSTITUTE,
                                      IpSubstituter,
                                      16
                                      );
    } else {
        /* IPv4 */
        char	IpSubstituter[4];

        IPv4AddressToNum(Substituter, IpSubstituter);

        return IpChunk_AddFromString(&(m->c),
                                     Ip,
                                     (int)IP_MISC_TYPE_SUBSTITUTE,
                                     IpSubstituter,
                                     4
                                     );
    }
}

static int IPMisc_Process(IPMisc *m,
                          char *DNSPackage, /* Without TCPLength */
                          int PackageLength
                          )
{
    DnsSimpleParser p;
    DnsSimpleParserIterator i;

    if( DnsSimpleParser_Init(&p, DNSPackage, PackageLength, FALSE) != 0 )
    {
        return IP_MISC_ACTION_NOTHING;
    }

    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
    {
        return IP_MISC_ACTION_NOTHING;
    }

    i.GotoAnswers(&i);
    while( i.Next(&i) != NULL && i.Purpose == DNS_RECORD_PURPOSE_ANSWER )
    {
        MiscType ActionType = IP_MISC_TYPE_UNKNOWN;
        const char *Data = NULL;
        int DataLength = 0;

        char *RowDataPos = i.RowData(&i);

        if( i.Klass != DNS_CLASS_IN )
        {
            continue;
        }

        switch( i.Type )
        {
        case DNS_TYPE_A:
            if( IpChunk_Find(&(m->c),
                             *(uint32_t *)RowDataPos,
                             (int *)&ActionType,
                             &Data)
               == FALSE )
            {
                continue;
            }
            DataLength = 4;
            break;

        case DNS_TYPE_AAAA:
            if( IpChunk_Find6(&(m->c), RowDataPos, (int *)&ActionType, &Data) == FALSE )
            {
                continue;
            }
            DataLength = 16;
            break;

        default:
            continue;
            break;
        }

        switch( ActionType )
        {
        case IP_MISC_TYPE_BLOCK:
            return IP_MISC_ACTION_BLOCK;
            break;

        case IP_MISC_TYPE_SUBSTITUTE:
            memcpy(RowDataPos, Data, DataLength);
            break;

        default:
            break;
        }
    }

    return IP_MISC_ACTION_NOTHING;
}

int IPMisc_Init(IPMisc *m)
{
    if( m == NULL || IpChunk_Init(&(m->c)) != 0 )
    {
        return -1;
    }

    m->AddBlockFromString = IPMisc_AddBlockFromString;
    m->AddSubstituteFromString = IPMisc_AddSubstituteFromString;
    m->Process = IPMisc_Process;

    return 0;
}
