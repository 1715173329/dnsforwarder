#include "hostsutils.h"
#include "dnsgenerator.h"

static const char *Match(HostsContainer *Container,
                         const char *Domain,
                         HostsRecordType Type,
                         const void **Result
                         )
{
    if( Container != NULL )
    {
        return Container->Find(Container, Domain, &Type, Result);
    }

    return NULL;
}

static BOOL CNameExisting(HostsContainer *Container, const char *Domain)
{
    return Match(Container, Domain, DNS_TYPE_CNAME, NULL) != NULL;
}

int Hosts_Try(IHeader *Header, int BufferLength, HostsContainer *Container)
{
	char *RequestEntity = (char *)(Header + 1);

	const char	*Result;
	const char	*MatchState;

	/** TODO: You should also check the queried class */
    if( Header->Type != DNS_TYPE_CNAME &&
        Header->Type != DNS_TYPE_A &&
        Header->Type != DNS_TYPE_AAAA
        )
    {
        return HOSTS_TRY_NONE;
    }

    if( Header->Type != DNS_TYPE_CNAME &&
        CNameExisting(Container, Header->Domain)
        )
    {
        return HOSTS_TRY_RECURSED;
    }

    MatchState = Match(Container,
                       Header->Domain,
                       Header->Type,
                       (const void **)&Result
                       );

	if( MatchState != NULL )
	{
	    DnsSimpleParser p;
	    BOOL HasEdns;
        DnsGenerator g;

        char *HereToGenerate = RequestEntity + Header->EntityLength;
        int LeftBufferLength =
                          BufferLength - sizeof(IHeader) - Header->EntityLength;

        int ResultLength;

	    if( DnsSimpleParser_Init(&p,
                                 RequestEntity,
                                 Header->EntityLength,
                                 FALSE
                                 )
            != 0 )
        {
            return HOSTS_TRY_NONE;
        }

        HasEdns = p.HasType(&p,
                            DNS_RECORD_PURPOSE_ADDITIONAL,
                            DNS_CLASS_UNKNOWN,
                            DNS_TYPE_OPT
                            );

        if( DnsGenerator_Init(&g,
                              HereToGenerate,
                              LeftBufferLength,
                              RequestEntity,
                              Header->EntityLength,
                              TRUE
                              )
           != 0)
        {
            return HOSTS_TRY_NONE;
        }

        g.Header->Flags.Direction = 1;
        g.Header->Flags.AuthoritativeAnswer = 0;
        g.Header->Flags.RecursionAvailable = 1;
        g.Header->Flags.ResponseCode = 0;
        g.Header->Flags.Type = 0;

        if( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER )
        {
            return HOSTS_TRY_NONE;
        }

        switch( Header->Type )
        {
        case DNS_TYPE_CNAME:
            if( g.CName(&g, "a", Result, 60) != 0 )
            {
                return HOSTS_TRY_NONE;
            }
            break;

        case DNS_TYPE_A:
            if( g.RawData(&g,
                          "a",
                          DNS_TYPE_A,
                          DNS_CLASS_IN,
                          Result,
                          4,
                          60
                          )
                != 0 )
            {
                return HOSTS_TRY_NONE;
            }
            break;

        case DNS_TYPE_AAAA:
            if( g.RawData(&g,
                          "a",
                          DNS_TYPE_AAAA,
                          DNS_CLASS_IN,
                          Result,
                          16,
                          60
                          )
                != 0 )
            {
                return HOSTS_TRY_NONE;
            }
            break;

        default:
            return HOSTS_TRY_NONE;
            break;
        }

        if( HasEdns )
        {
            while( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ADDITIONAL );
            if( g.EDns(&g, 1280) != 0 )
            {
                return HOSTS_TRY_NONE;
            }
        }

        /* g will no longer be needed, and can be crapped */
        ResultLength = DNSCompress(HereToGenerate, g.Length(&g));
        if( ResultLength < 0 )
        {
            return HOSTS_TRY_NONE;
        }

        Header->EntityLength = ResultLength;
        memmove(RequestEntity, HereToGenerate, ResultLength);

        IHeader_SendBack(Header);

        return HOSTS_TRY_OK;
	} else {
	    return HOSTS_TRY_NONE;
	}
}

int Hosts_RecursiveQuery(SOCKET Socket, /* Both for sending and receiving */
                         Address_Type *BackAddress,
                         int Identifier,
                         const char *Name,
                         DNSRecordType Type
                         )
{
    static const char DNSHeader[DNS_HEADER_LENGTH] = {
        00, 00, /* QueryIdentifier */
        01, 00, /* Flags */
        00, 01, /* QuestionCount */
        00, 00, /* AnswerCount */
        00, 00, /* NameServerCount */
        00, 00, /* AdditionalCount */
    };

    static char RequestBuffer[2048];
    static IHeader *Header = (IHeader *)RequestBuffer;
    static char *RequestEntity = RequestBuffer + sizeof(IHeader);

	DnsGenerator g;

	if( DnsGenerator_Init(&g,
                          RequestEntity,
                          sizeof(RequestBuffer) - sizeof(IHeader),
                          DNSHeader,
                          DNS_HEADER_LENGTH,
                          FALSE
                          )
        != 0 )
    {
        return -323;
    }

    g.CopyIdentifier(&g, Identifier);

    if( g.Question(&g, Name, Type, DNS_CLASS_IN) != 0 )
    {
        return -328;
    }

    IHeader_Fill(Header,
                 TRUE,
                 RequestEntity,
                 g.Length(&g),
                 &(BackAddress->Addr),
                 Socket,
                 BackAddress->family,
                 "CNameRedirect"
                 );

    return MMgr_Send(Header, sizeof(RequestBuffer));
}
