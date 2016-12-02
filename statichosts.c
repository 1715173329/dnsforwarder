#include <ctype.h>
#include "statichosts.h"
#include "dnsgenerator.h"
#include "readconfig.h"
#include "utils.h"

HostsContainer	MainStaticContainer;

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

int Hosts_InitContainer(HostsContainer	*Container)
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

	return 0;
}

HostsRecordType Hosts_LoadFromMetaLine(HostsContainer *Container, char *MetaLine)
{
	const char *IPOrCName;
	const char *Domain;

	IPOrCName = GoToNextNonSpace(MetaLine);
	if( IPOrCName == NULL )
	{
		INFO("Unrecognisable hosts : %s\n", MetaLine);
		return HOSTS_TYPE_UNKNOWN;
	}

	Domain = GetKeyNameAndValue((char *)IPOrCName, "\t ");
	if( Domain == NULL )
	{
		INFO("Unrecognisable hosts : %s\n", MetaLine);
		return HOSTS_TYPE_UNKNOWN;
	}

	return Hosts_AddToContainer(Container, IPOrCName, Domain);
}

int StaticHosts_Init(ConfigFileInfo *ConfigInfo)
{
	int		IPv4Count = 0, IPv6Count = 0, CNameCount = 0, ExcludedCount = 0, GoodIpListCount = 0;

	StringList *AppendHosts = ConfigGetStringList(ConfigInfo, "AppendHosts");
	StringListIterator  sli;

	const char *Itr;
	char Buffer[2 * DOMAIN_NAME_LENGTH_MAX + 2];

	if( Hosts_InitContainer(&MainStaticContainer) != 0 )
	{
		return -1;
	}

	if( AppendHosts == NULL )
	{
		return -2; /* Important */
	}

	if( StringListIterator_Init(&sli, AppendHosts) != 0 )
    {
        return -3;
    }

	Itr = sli.Next(&sli);
	while( Itr != NULL )
	{
		if( strlen(Itr) > sizeof(Buffer) - 1 )
		{
			ERRORMSG("Hosts is too long : %s\n", Buffer);
		} else {
			strcpy(Buffer, Itr);
			Buffer[sizeof(Buffer) - 1] = '\0';

			switch( Hosts_LoadFromMetaLine(&MainStaticContainer, Buffer) )
			{
				case HOSTS_TYPE_A:
					++IPv4Count;
					break;

				case HOSTS_TYPE_AAAA:
					++IPv6Count;
					break;

				case HOSTS_TYPE_CNAME:
					++CNameCount;
					break;

				case HOSTS_TYPE_EXCLUEDE:
					++ExcludedCount;
					break;

                case HOSTS_TYPE_CNAME_EXCLUEDE:
                    ++CNameCount;
                    ++ExcludedCount;
                    break;

                case HOSTS_TYPE_GOOD_IP_LIST:
                    ++GoodIpListCount;
                    break;

				default:
					break;
			}
		}

		Itr = sli.Next(&sli);
	}

	INFO("Loading Appendhosts completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Redirections, %d items are excluded, %d items point to GoodIPLists.\n",
		IPv4Count,
		IPv6Count,
		CNameCount,
		ExcludedCount,
		GoodIpListCount
		);

	return 0;
}
