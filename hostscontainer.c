#include "hostscontainer.h"
#include "logs.h"

typedef struct _HostsPosition{
    HostsRecordType Type;
	void    *Position;
} HostsPosition;

PRIFUNC HostsRecordType HostsContainer_DetermineType(const char *IPOrCName)
{
	if( IPOrCName == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	/* Good IP List */
	if( *IPOrCName == '<' && IPOrCName[strlen(IPOrCName) - 1] == '>' )
	{
		return HOSTS_TYPE_GOOD_IP_LIST;
	}

	/* A host IPOrCName started with "@@ " is excluded */
	if( *IPOrCName == '@' && *(IPOrCName + 1) == '@' )
	{
		return HOSTS_TYPE_EXCLUEDE;
	}

	if( isxdigit(*IPOrCName) )
	{
		const char *Itr;
		/* Check if it is IPv6 */
		if( strchr(IPOrCName, ':') != NULL )
		{
			return HOSTS_TYPE_AAAA;
		}

		/* Check if it is CNAME */
		for(Itr = IPOrCName; *Itr != '\0'; ++Itr)
		{
			if( isalpha(*Itr) || *Itr == '-' )
			{
				return HOSTS_TYPE_CNAME;
			}
		}

		for(Itr = IPOrCName; *Itr != '\0'; ++Itr)
		{
			if( isdigit(*Itr) || *Itr == '.' )
			{
				return HOSTS_TYPE_A;
			}
		}

		return HOSTS_TYPE_UNKNOWN;

	} else {

		if( *IPOrCName == ':' )
		{
			return HOSTS_TYPE_AAAA;
		}

		for(; *IPOrCName != '\0'; ++IPOrCName)
		{
			if( !isalnum(*IPOrCName) && *IPOrCName != '-' && *IPOrCName != '.' )
			{
				return HOSTS_TYPE_UNKNOWN;
			}
		}

		return HOSTS_TYPE_CNAME;
	}
}

PUBFUNC const char *HostsContainer_Find(HostsContainer  *Container,
                                        const char      *Name,
                                        HostsRecordType *Type
                                        )
{
	HostsPosition *IP;

	if( StringChunk_Match(&(Container -> Mappings), Name, NULL, (void **)&IP) )
	{
	    if( Type == NULL )
        {
            return IP->Position;
        } else if( *Type == HOSTS_TYPE_UNKNOWN )
        {
            *Type = IP->Type;
            return IP->Position;
        } else if( *Type == IP->Type ){
            return IP->Position;
        }
	}

    return NULL;
}

PRIFUNC int HostsContainer_AddIPV6(HostsContainer *Container,
                                   const char *IPOrCName,
                                   const char *Domain
                                   )
{
	HostsPosition	r;
	char			NumericIP[16];

	StableBuffer    *sb;

	if( HostsContainer_Find(Container, Domain, NULL) )
	{
		INFO("Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

	sb = &(Container->IPs);

	IPv6AddressToNum(IPOrCName, NumericIP);

    r.Position = sb->Add(sb, NumericIP, 16, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

    r.Type = HOSTS_TYPE_AAAA;

	StringChunk_Add(&(Container -> Mappings), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

PRIFUNC int HostsContainer_AddIPV4(HostsContainer *Container,
                                   const char *IPOrCName,
                                   const char *Domain
                                   )
{
	HostsPosition	r;
	char			NumericIP[4];

	StableBuffer    *sb;

	if( HostsContainer_Find(Container, Domain, NULL) )
	{
		INFO("Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

	sb = &(Container->IPs);

	IPv4AddressToNum(IPOrCName, NumericIP);

    r.Position = sb->Add(sb, NumericIP, 4, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

    r.Type = HOSTS_TYPE_A;

	StringChunk_Add(&(Container -> Mappings), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

PRIFUNC int HostsContainer_AddCName(HostsContainer *Container,
                                    const char *IPOrCName,
                                    const char *Domain
                                    )
{
	HostsPosition	r;

	StableBuffer    *sb;

	if( strlen(Domain) > DOMAIN_NAME_LENGTH_MAX )
	{
		ERRORMSG("Host is too long : %s %s\n", IPOrCName, Domain);
		return -1;
	}

	if( HostsContainer_Find(Container, Domain, NULL) )
	{
		INFO("Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

    sb = &(Container->IPs);

    r.Position = sb->Add(sb, IPOrCName, strlen(IPOrCName) + 1, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

    r.Type = HOSTS_TYPE_CNAME;

	StringChunk_Add(&(Container -> Mappings), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

PRIFUNC int HostsContainer_AddGoodIpList(HostsContainer *Container,
                                         const char *ListName,
                                         const char *Domain
                                         )
{
	HostsPosition	r;

	StableBuffer    *sb;
	char            Trimed[128];

	if( strlen(Domain) > DOMAIN_NAME_LENGTH_MAX )
	{
		ERRORMSG("Host is too long : %s %s\n", ListName, Domain);
		return -1;
	}

	if( HostsContainer_Find(Container, Domain, NULL) )
	{
		INFO("Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

    sb = &(Container->IPs);

    sscanf(ListName, "<%127[^>]", Trimed);
    r.Position = sb->Add(sb, Trimed, strlen(Trimed) + 1, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

    r.Type = HOSTS_TYPE_GOOD_IP_LIST;

	StringChunk_Add(&(Container -> Mappings), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

PRIFUNC int HostsContainer_AddExcluded(HostsContainer *Container,
                                       const char *Domain
                                       )
{
    HostsPosition	r = { HOSTS_TYPE_EXCLUEDE, NULL };

	if( HostsContainer_Find(Container, Domain, NULL) )
	{
		INFO("Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

	StringChunk_Add(&(Container -> Mappings),
                    Domain,
                    (const char *)&r,
                    sizeof(HostsPosition)
                    );

	return 0;
}

PRIFUNC HostsRecordType HostsContainer_Add(HostsContainer *Container,
                                           const char *IPOrCName,
                                           const char *Domain
                                           )
{
	switch( HostsContainer_DetermineType(IPOrCName) )
	{
		case HOSTS_TYPE_AAAA:
			if( HostsContainer_AddIPV6(Container, IPOrCName, Domain) != 0)
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_AAAA;
			}
			break;

		case HOSTS_TYPE_A:
			if( HostsContainer_AddIPV4(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_A;
			}
			break;

		case HOSTS_TYPE_CNAME:
			if( HostsContainer_AddCName(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_CNAME;
			}
			break;

		case HOSTS_TYPE_EXCLUEDE:
			if( HostsContainer_AddExcluded(Container, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_EXCLUEDE;
			}
			break;

		case HOSTS_TYPE_GOOD_IP_LIST:
			if( HostsContainer_AddGoodIpList(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_GOOD_IP_LIST;
			}
			break;

		default:
			INFO("Unrecognisable host : %s %s\n", IPOrCName, Domain);
			return HOSTS_TYPE_UNKNOWN;
			break;
	}
}

PUBFUNC HostsRecordType HostsContainer_Load(HostsContainer *Container,
                                            const char *MetaLine
                                            )
{
	char IPOrCName[DOMAIN_NAME_LENGTH_MAX + 1];
	char Domain[DOMAIN_NAME_LENGTH_MAX + 1];

	if( sscanf(MetaLine,
               "%" STRINGIZINGINT(DOMAIN_NAME_LENGTH_MAX) "s%" STRINGIZINGINT(DOMAIN_NAME_LENGTH_MAX) "s",
               IPOrCName,
               Domain
               )
     != 2 )
    {
		INFO("Unrecognisable hosts : %s\n", MetaLine);
		return HOSTS_TYPE_UNKNOWN;
    }

	return HostsContainer_Add(Container, IPOrCName, Domain);
}

PUBFUNC void HostsContainer_Free(HostsContainer *Container)
{
	StringChunk_Free(&(Container -> Mappings), TRUE);
	Container->IPs.Free(&(Container->IPs));
}

int HostsContainer_Init(HostsContainer *Container)
{
	if( StringChunk_Init(&(Container -> Mappings), NULL) != 0 )
	{
		return -2;
	}

	if( StableBuffer_Init(&(Container -> IPs)) != 0 )
	{
		return -6;
	}

	Container->Load = HostsContainer_Load;
	Container->Find = HostsContainer_Find;
	Container->Free = HostsContainer_Free;

	return 0;
}
