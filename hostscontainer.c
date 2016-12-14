#include "hostscontainer.h"
#include "logs.h"

typedef struct _HostsPosition{
	void    *Position;
} HostsPosition;

static HostsRecordType Hosts_DetermineIPTypes(const char *IPOrCName)
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

	if( *IPOrCName == '@' && !isspace(*(IPOrCName + 1)) )
	{
		return HOSTS_TYPE_CNAME_EXCLUEDE;
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

static int Hosts_AddIPV6ToContainer(HostsContainer *Container, const char *IPOrCName, const char *Domain)
{
	HostsPosition	r;
	char			NumericIP[16];

	StableBuffer    *sb;

	if( StringChunk_Match_NoWildCard(&(Container -> Ipv6Hosts), Domain, NULL, NULL) == TRUE )
	{
		INFO("IPv6 Host is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

	sb = &(Container->IPs);

	IPv6AddressToNum(IPOrCName, NumericIP);

    r.Position = sb->Add(sb, NumericIP, 16, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

	StringChunk_Add(&(Container -> Ipv6Hosts), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

static int Hosts_AddIPV4ToContainer(HostsContainer *Container, const char *IPOrCName, const char *Domain)
{
	HostsPosition	r;
	char			NumericIP[4];

	StableBuffer    *sb;

	if( StringChunk_Match_NoWildCard(&(Container -> Ipv4Hosts), Domain, NULL, NULL) == TRUE )
	{
		INFO("IPv4 Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

	sb = &(Container->IPs);

	IPv4AddressToNum(IPOrCName, NumericIP);

    r.Position = sb->Add(sb, NumericIP, 4, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

	StringChunk_Add(&(Container -> Ipv4Hosts), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

static int Hosts_AddCNameContainer(HostsContainer *Container, const char *IPOrCName, const char *Domain)
{
	HostsPosition	r;

	StableBuffer    *sb;

	if( strlen(Domain) > DOMAIN_NAME_LENGTH_MAX )
	{
		ERRORMSG("Hosts is too long : %s %s\n", IPOrCName, Domain);
		return -1;
	}

	if( StringChunk_Match_NoWildCard(&(Container -> CNameHosts), Domain, NULL, NULL) == TRUE )
	{
		INFO("CName redirection domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

    sb = &(Container->IPs);

    r.Position = sb->Add(sb, IPOrCName, strlen(IPOrCName) + 1, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

	StringChunk_Add(&(Container -> CNameHosts), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}


static int Hosts_AddGoodIpListContainer(HostsContainer *Container, const char *ListName, const char *Domain)
{
	HostsPosition	r;

	StableBuffer    *sb;
	char            Trimed[128];

	if( strlen(Domain) > DOMAIN_NAME_LENGTH_MAX )
	{
		ERRORMSG("Hosts is too long : %s %s\n", ListName, Domain);
		return -1;
	}

	if( StringChunk_Match_NoWildCard(&(Container -> GoodIpLists), Domain, NULL, NULL) == TRUE )
	{
		INFO("Good IP list domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

    sb = &(Container->IPs);

    sscanf(ListName, "<%127[^>]", Trimed);
    r.Position = sb->Add(sb, Trimed, strlen(Trimed) + 1, TRUE);

    if( r.Position == NULL )
    {
        return -1;
    }

	StringChunk_Add(&(Container -> GoodIpLists), Domain, (const char *)&r, sizeof(HostsPosition));

	return 0;
}

static int Hosts_AddExcludedContainer(HostsContainer *Container, const char *Domain)
{
	if( StringChunk_Match_NoWildCard(&(Container -> ExcludedDomains), Domain, NULL, NULL) == TRUE )
	{
		INFO("Excluded Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
		return -1;
	}

	StringChunk_Add(&(Container -> ExcludedDomains), Domain, NULL, 0);

	return 0;
}

static HostsRecordType Hosts_AddToContainer(HostsContainer *Container, const char *IPOrCName, const char *Domain)
{
	switch( Hosts_DetermineIPTypes(IPOrCName) )
	{
		case HOSTS_TYPE_AAAA:
			if( Hosts_AddIPV6ToContainer(Container, IPOrCName, Domain) != 0)
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_AAAA;
			}
			break;

		case HOSTS_TYPE_A:
			if( Hosts_AddIPV4ToContainer(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_A;
			}
			break;

		case HOSTS_TYPE_CNAME_EXCLUEDE:
			++IPOrCName;

			if( Hosts_AddExcludedContainer(Container, IPOrCName) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			}

			if( Hosts_AddCNameContainer(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_CNAME_EXCLUEDE;
			}
			break;

		case HOSTS_TYPE_CNAME:
			if( Hosts_AddCNameContainer(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_CNAME;
			}
			break;

		case HOSTS_TYPE_EXCLUEDE:
			if( Hosts_AddExcludedContainer(Container, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_EXCLUEDE;
			}
			break;

		case HOSTS_TYPE_GOOD_IP_LIST:
			if( Hosts_AddGoodIpListContainer(Container, IPOrCName, Domain) != 0 )
			{
				return HOSTS_TYPE_UNKNOWN;
			} else {
				return HOSTS_TYPE_GOOD_IP_LIST;
			}
			break;

		default:
			INFO("Unrecognisable hosts : %s %s\n", IPOrCName, Domain);
			return HOSTS_TYPE_UNKNOWN;
			break;
	}
}

PRIFUNC HostsRecordType HostsContainer_Load(HostsContainer *Container,
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

	return Hosts_AddToContainer(Container, IPOrCName, Domain);
}

PRIFUNC void HostsContainer_Free(HostsContainer *Container)
{
	StringChunk_Free(&(Container -> Ipv4Hosts), FALSE);
	StringChunk_Free(&(Container -> Ipv6Hosts), FALSE);
	StringChunk_Free(&(Container -> CNameHosts), FALSE);
	StringChunk_Free(&(Container -> ExcludedDomains), FALSE);
    Container->Domains.Free(&(Container -> Domains));
	Container->IPs.Free(&(Container->IPs));
}

int HostsContainer_Init(HostsContainer *Container)
{
	if( StringList_Init(&(Container -> Domains), NULL, NULL) != 0 )
	{
		return -1;
	}

	if( StringChunk_Init(&(Container -> Ipv4Hosts), &(Container -> Domains)) != 0 )
	{
		return -2;
	}
	if( StringChunk_Init(&(Container -> Ipv6Hosts), &(Container -> Domains)) != 0 )
	{
		return -3;
	}
	if( StringChunk_Init(&(Container -> CNameHosts), &(Container -> Domains)) != 0 )
	{
		return -4;
	}
	if( StringChunk_Init(&(Container -> ExcludedDomains), &(Container -> Domains)) != 0 )
	{
		return -4;
	}
	if( StringChunk_Init(&(Container -> GoodIpLists), &(Container -> Domains)) != 0 )
	{
		return -5;
	}
	if( StableBuffer_Init(&(Container -> IPs)) != 0 )
	{
		return -6;
	}

	Container->Load = HostsContainer_Load;
	Container->Free = HostsContainer_Free;

	return 0;
}
