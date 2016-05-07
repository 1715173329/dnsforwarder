#include <string.h>
#include <limits.h>
#include "readconfig.h"
#include "goodiplist.h"
#include "request_response.h"
#include "utils.h"
#include "debug.h"

typedef struct _CountDownMeta{
	int	TimeLeft;
	int	Interval;
	Array	List;
} CountDownMeta;

static StringChunk	*GoodIpList = NULL;

/* GoodIPList list1 1000 */
static int InitListsAndTimes(ConfigFileInfo *ConfigInfo)
{
	StringList	*l	=	ConfigGetStringList(ConfigInfo, "GoodIPList");
	const char	*Itr	=	NULL;

	if( l == NULL )
	{
		return -1;
	}

	GoodIpList = SafeMalloc(sizeof(StringChunk));
	if( GoodIpList != NULL && StringChunk_Init(GoodIpList, NULL) != 0 )
	{
		return -3;
	}

	Itr = StringList_GetNext(l, NULL);
    while( Itr != NULL )
    {
		CountDownMeta	m = {0, 0, Array_Init_Static(sizeof(struct sockaddr_in))};
		char n[128];
		int i;

		sscanf(Itr, "%127s%d", n, &i);

		if( i <= 0 )
		{
			ERRORMSG("List is invalid : %s\n", Itr);
			continue;
		}
        m.Interval = i;
		StringChunk_Add(GoodIpList, n, (const char *)&m, sizeof(CountDownMeta));

		Itr = StringList_GetNext(l, Itr);
    }

    return 0;
}

/* GoodIPListAddIP list1 ip:port */
static int AddToLists(ConfigFileInfo *ConfigInfo)
{
	StringList	*l	=	ConfigGetStringList(ConfigInfo, "GoodIPListAddIP");
	const char	*Itr	=	NULL;

	if( l == NULL )
	{
		return -1;
	}

	Itr = StringList_GetNext(l, NULL);
    while( Itr != NULL )
    {
		CountDownMeta	*m = NULL;
		char n[128], ip_str[LENGTH_OF_IPV4_ADDRESS_ASCII];
		int Port;
		struct sockaddr_in	ip;

		sscanf(Itr, "%127s%*[^0123456789]%15[^:]:%d", n, ip_str, &Port);
		ip.sin_port = htons(Port);
		ip.sin_family = AF_INET; /* IPv4 only */

		IPv4AddressToNum(ip_str, &(ip.sin_addr));

		if( StringChunk_Match_NoWildCard(GoodIpList, n, NULL, (char **)&m) == FALSE)
		{
			ERRORMSG("List is not found : %s\n", Itr);
			continue;
		}

		Array_PushBack(&(m -> List), &ip, NULL);

		Itr = StringList_GetNext(l, Itr);
    }

    return 0;
}

/* The fastest returned */
static struct sockaddr_in *CheckAList(struct sockaddr_in *Ips, int Count)
{
	static Array	SocketsA	=	Array_Init_Static(sizeof(SOCKET));
	static const SOCKET	InvalidSocket	=	INVALID_SOCKET;

	fd_set	rfd;
	struct timeval	Time	=	{5, 0};
	int	MaxFd	=	-1;

	struct sockaddr_in *Fastest = NULL;

	int	i; /* For loop use */

	Array_Clear(&SocketsA);
	Array_Fill(&SocketsA, Count, &InvalidSocket);
	FD_ZERO(&rfd);

	for( i = 0; i != Count; ++i )
    {
		SOCKET	skt;

		skt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if( skt == INVALID_SOCKET )
		{
			continue;
		}
		SetSocketNonBlock(skt, TRUE);

		if( connect(skt, (const struct sockaddr *)&(Ips[i]), sizeof(struct sockaddr_in)) != 0 && FatalErrorDecideding(GET_LAST_ERROR()) != 0 )
		{
			CLOSE_SOCKET(skt);
			continue;
		}

		if( (int)skt > MaxFd )
		{
			MaxFd = skt;
		}

		FD_SET(skt, &rfd);
		Array_SetToSubscript(&SocketsA, i, &skt);
    }

    if( MaxFd < 0 )
    {
		return NULL;
    }

	switch( select(MaxFd + 1, NULL, &rfd, NULL, &Time) )
	{
		case 0:
		case SOCKET_ERROR:
			for( i = 0; i < Array_GetUsed(&SocketsA); ++i)
			{
				const SOCKET *rs = (const SOCKET *)Array_GetBySubscript(&SocketsA, i);

				if( rs != NULL && *rs != INVALID_SOCKET )
				{
					CLOSE_SOCKET(*rs);
				}
			}
			return NULL;
			break;

		default:
			for( i = 0; i < Array_GetUsed(&SocketsA); ++i)
			{
				const SOCKET *rs = (const SOCKET *)Array_GetBySubscript(&SocketsA, i);

				if( rs != NULL && *rs != INVALID_SOCKET )
				{
					if( FD_ISSET(*rs, &rfd) )
					{
						Fastest = &(Ips[i]);
					}
					CLOSE_SOCKET(*rs);
				}
			}
			break;
	}

	return Fastest;
}

static int GetMinTime(void)
{
	int32_t i = 0;
	int Min = INT_MAX;
	const char  *str = NULL;

	const CountDownMeta	*m;

    str = StringChunk_Enum_NoWildCard(GoodIpList, &i, (char **)&m);
    while( str != NULL )
	{
		if( m != NULL && Min > (m -> TimeLeft) )
		{
			Min = (m -> TimeLeft);
		}
		str = StringChunk_Enum_NoWildCard(GoodIpList, &i, (char **)&m);
	}

	return Min;
}

static void BatchMinus(int Min)
{
	int32_t i = 0;
	const char  *str;

	CountDownMeta	*m;

    str = StringChunk_Enum_NoWildCard(GoodIpList, &i, (char **)&m);
    while( str != NULL )
	{
		if( m != NULL)
		{
			if( m -> TimeLeft != Min)
			{
				m -> TimeLeft -= Min;
			} else {
                m -> TimeLeft = m -> Interval;
			}

		}
		str = StringChunk_Enum_NoWildCard(GoodIpList, &i, (char **)&m);
	}
}

static void ThreadJod(int Min)
{
    int32_t i = 0; /* For enum use */
    const char  *str;
	const CountDownMeta *m;

    str = StringChunk_Enum_NoWildCard(GoodIpList, &i, (char **)&m);
    while( str != NULL )
	{
		if( m != NULL && m -> TimeLeft == Min )
		{
			struct sockaddr_in *Fastest, *First;

			Fastest = CheckAList((struct sockaddr_in *)Array_GetRawArray(&(m -> List)), Array_GetUsed(&(m -> List)));
			if( Fastest != NULL )
			{
                INFO("The fastest ip for `%s' is %s\n", str, inet_ntoa(Fastest -> sin_addr));
				First = Array_GetBySubscript(&(m -> List), 0);
				if( First != NULL )
				{
					struct sockaddr_in t;
					memcpy(&t, Fastest, sizeof(struct sockaddr_in));
					memcpy(Fastest, First, sizeof(struct sockaddr_in));
					memcpy(First, &t, sizeof(struct sockaddr_in));

				}
			} else {
			    INFO("Checking list `%s' timeout.\n", str);
			}
		}
		str = StringChunk_Enum_NoWildCard(GoodIpList, &i, (char **)&m);
	}
}

static void ThreadLoop(void)
{
	int Min = 0;
	while(TRUE)
	{
		ThreadJod(Min);
		BatchMinus(Min);
		Min = GetMinTime();
		SLEEP(Min);
	}
}

int GoodIpList_Init(ConfigFileInfo *ConfigInfo)
{
	ThreadHandle	t;

	if( InitListsAndTimes(ConfigInfo) != 0 )
	{
		return -1;
	}

	if( AddToLists(ConfigInfo) != 0 )
	{
		return -2;
	}

	CREATE_THREAD(ThreadLoop, NULL, t);
	DETACH_THREAD(t);

	return 0;
}

const char *GoodIpList_Get(const char *List)
{
    CountDownMeta   *m;
    if( StringChunk_Match_NoWildCard(GoodIpList, List, NULL, (char **)&m) == TRUE )
    {
        return (const char *)&(((const struct sockaddr_in *)Array_GetBySubscript(&(m -> List), 0)) -> sin_addr);
    } else {
        return NULL;
    }
}
