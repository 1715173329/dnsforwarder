#include <ctype.h>
#include "statichosts.h"
#include "dnsgenerator.h"
#include "readconfig.h"
#include "utils.h"

HostsContainer	MainStaticContainer;

static int32_t Hosts_IdenticalToLast(HostsContainer	*Container,
										HostsRecordType	CurrentType,
										const char		*CurrentContent,
										int				CurrentLength
										)
{
	static HostsContainer *LastContainer = NULL;
	static HostsRecordType LastType = HOSTS_TYPE_UNKNOWN;
	static int32_t LastOffset = 0;
	static int32_t LastLength = 0;

	if( LastContainer == NULL || LastContainer != Container )
	{
		LastContainer = Container;
		LastType = CurrentType;
		LastOffset = 0;
		LastLength = CurrentLength;
		return -1;
	}

	if( LastType == HOSTS_TYPE_UNKNOWN )
	{
		LastType = CurrentType;
		LastOffset = 0;
		LastLength = CurrentLength;
		return -1;
	}

	if( LastType == CurrentType )
	{
		if( memcmp(ExtendableBuffer_GetPositionByOffset(&(Container -> IPs), LastOffset),
					CurrentContent,
					CurrentLength
					) == 0
			)
		{
			return LastOffset;
		} else {
			LastOffset += LastLength;
			LastLength = CurrentLength;
			return -1;
		}
	} else {
		LastType = CurrentType;
		LastOffset += LastLength;
		LastLength = CurrentLength;
		return -1;
	}

}

static HostsRecordType Hosts_DetermineIPTypes(const char *IPOrCName)
{
	if( IPOrCName == NULL )
	{
		return HOSTS_TYPE_UNKNOWN;
	}

	/* A hosts IPOrCName started with "@@ " is excluded */
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

static HostsRecordType Hosts_AddToContainer(HostsContainer *Container, const char *IPOrCName, const char *Domain)
{
	OffsetOfHosts	r;
	char			NumericIP[16];

	switch( Hosts_DetermineIPTypes(IPOrCName) )
	{
		case HOSTS_TYPE_AAAA:
			if( StringChunk_Match_NoWildCard(&(Container -> Ipv6Hosts), Domain, NULL, NULL) == TRUE )
			{
				INFO("IPv6 Host is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			IPv6AddressToNum(IPOrCName, NumericIP);

			r.Offset = Hosts_IdenticalToLast(Container, HOSTS_TYPE_AAAA, NumericIP, 16);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), NumericIP, 16);

				if( r.Offset < 0 )
				{
					return HOSTS_TYPE_UNKNOWN;
				}

			}

			StringChunk_Add(&(Container -> Ipv6Hosts), Domain, (const char *)&r, sizeof(OffsetOfHosts));

			return HOSTS_TYPE_AAAA;
			break;

		case HOSTS_TYPE_A:
			if( StringChunk_Match_NoWildCard(&(Container -> Ipv4Hosts), Domain, NULL, NULL) == TRUE )
			{
				INFO("IPv4 Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			IPv4AddressToNum(IPOrCName, NumericIP);

			r.Offset = Hosts_IdenticalToLast(Container, HOSTS_TYPE_A, NumericIP, 4);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), NumericIP, 4);

				if( r.Offset < 0 )
				{
					return HOSTS_TYPE_UNKNOWN;
				}

			}

			StringChunk_Add(&(Container -> Ipv4Hosts), Domain, (const char *)&r, sizeof(OffsetOfHosts));

			return HOSTS_TYPE_A;
			break;

		case HOSTS_TYPE_CNAME:
			if( strlen(Domain) > DOMAIN_NAME_LENGTH_MAX )
			{
				ERRORMSG("Hosts is too long : %s %s\n", IPOrCName, Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			if( StringChunk_Match_NoWildCard(&(Container -> CNameHosts), Domain, NULL, NULL) == TRUE )
			{
				INFO("CName redirection domain is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			r.Offset = Hosts_IdenticalToLast(Container, HOSTS_TYPE_CNAME, IPOrCName, strlen(IPOrCName) + 1);

			if( r.Offset < 0 )
			{

				r.Offset = ExtendableBuffer_Add(&(Container -> IPs), IPOrCName, strlen(IPOrCName) + 1);

				if( r.Offset < 0 )
				{
					return HOSTS_TYPE_UNKNOWN;
				}

			}

			StringChunk_Add(&(Container -> CNameHosts), Domain, (const char *)&r, sizeof(OffsetOfHosts));

			return HOSTS_TYPE_CNAME;
			break;

		case HOSTS_TYPE_EXCLUEDE:
			if( StringChunk_Match_NoWildCard(&(Container -> ExcludedDomains), Domain, NULL, NULL) == TRUE )
			{
				INFO("Excluded Host domain is duplicated : %s, take only the first occurrence.\n", Domain);
				return HOSTS_TYPE_UNKNOWN;
			}

			StringChunk_Add(&(Container -> ExcludedDomains), Domain, NULL, 0);

			return HOSTS_TYPE_EXCLUEDE;
			break;

		default:
			INFO("Unrecognisable hosts : %s %s\n", IPOrCName, Domain);
			return HOSTS_TYPE_UNKNOWN;
			break;
	}
}

int Hosts_InitContainer(HostsContainer	*Container)
{
	if( StringList_Init(&(Container -> Domains), NULL, ',') != 0 )
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
	if( ExtendableBuffer_Init(&(Container ->IPs), 0, -1) != 0 )
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

	Domain = GetKeyNameAndValue(IPOrCName, "\t ");
	if( Domain == NULL )
	{
		INFO("Unrecognisable hosts : %s\n", MetaLine);
		return HOSTS_TYPE_UNKNOWN;
	}

	return Hosts_AddToContainer(Container, IPOrCName, Domain);
}

int StaticHosts_Init(ConfigFileInfo *ConfigInfo)
{
	int		IPv4Count = 0, IPv6Count = 0, CNameCount = 0, ExcludedCount = 0;

	StringList *AppendHosts = ConfigGetStringList(ConfigInfo, "AppendHosts");
	const char *Itr;
	char Buffer[2 * DOMAIN_NAME_LENGTH_MAX + 2];

	if( Hosts_InitContainer(&MainStaticContainer) != 0 )
	{
		return -1;
	}

	if( AppendHosts == NULL )
	{
		return -1;
	}

	Itr = StringList_GetNext(AppendHosts, NULL);
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

				default:
					break;
			}
		}

		Itr = StringList_GetNext(AppendHosts, Itr);
	}

	INFO("Loading Appendhosts completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Redirections, %d items are excluded.\n",
		IPv4Count,
		IPv6Count,
		CNameCount,
		ExcludedCount);


	return 0;
}
