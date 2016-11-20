#include <time.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif
#include "querydnsbase.h"
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "hosts.h"
#include "utils.h"
#include "filter.h"
#include "stringlist.h"
#include "domainstatistic.h"
#include "request_response.h"

void ShowBlockedMessage(const char *RequestingDomain, char *Package, int PackageLength, const char *Message)
{
	char DateAndTime[32];
	char InfoBuffer[1024];

	if( ShowMessages == TRUE || PRINTON )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		InfoBuffer[0] = '\0';
		GetAllAnswers(Package, PackageLength, InfoBuffer, sizeof(InfoBuffer));
	}

	if( ShowMessages == TRUE )
	{
		printf("%s[B][%s] %s :\n%s", DateAndTime, RequestingDomain, Message == NULL ? "" : Message, InfoBuffer);
	}

	DEBUG_FILE("%s[B][%s] %s :\n%s", DateAndTime, RequestingDomain, Message == NULL ? "" : Message, InfoBuffer);
}

void ShowFatalMessage(const char *Message, int ErrorCode)
{
	char	ErrorMessage[320];

	ErrorMessage[0] = '\0';

	if( ErrorMessages == TRUE || PRINTON )
	{
		GetErrorMsg(ErrorCode, ErrorMessage, sizeof(ErrorMessage));
	}

	if( ErrorMessages == TRUE )
	{
		printf("[ERROR] %s %d : %s\n", Message, ErrorCode, ErrorMessage);
	}

	DEBUG_FILE("[ERROR] %s %d : %s\n", Message, ErrorCode, ErrorMessage);

}

static int QueryFromServer(char *Content, int ContentLength, SOCKET ThisSocket)
{
	ControlHeader	*Header = (ControlHeader *)Content;

	int		Interface;

	/* Determine whether the secondaries are used */
	if(	IsExcludedDomain(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue)))
	{
		Interface = INTERNAL_INTERFACE_SECONDARY;
	} else {
		Interface = INTERNAL_INTERFACE_PRIMARY;
	}

	return InternalInterface_SendTo(Interface, ThisSocket, Content, ContentLength);
}

#define DNS_FETCH_FROM_HOSTS_OK	0
#define DNS_FETCH_FROM_HOSTS_NONE_RESULT	(-1)
#define DNS_FETCH_FROM_HOSTS_DISABLE_IPV6	(-2)
static int DNSFetchFromHosts(char *Content, int ContentLength, int BufferLength, SOCKET ThisSocket)
{
	switch ( Hosts_Try(Content, &ContentLength, BufferLength) )
	{
		case MATCH_STATE_NONE:
		case MATCH_STATE_DISABLED:
			return DNS_FETCH_FROM_HOSTS_NONE_RESULT;
			break;

		case MATCH_STATE_DISABLE_IPV6:
			return DNS_FETCH_FROM_HOSTS_DISABLE_IPV6;
			break;

		case MATCH_STATE_ONLY_CNAME:
			if( InternalInterface_SendTo(INTERNAL_INTERFACE_HOSTS, ThisSocket, Content, ContentLength) > 0 )
			{
				return DNS_FETCH_FROM_HOSTS_OK;
			} else {
				return DNS_FETCH_FROM_HOSTS_NONE_RESULT;
			}

			break;

		case MATCH_STATE_PERFECT:
			return ContentLength;
			break;

		default:
			return DNS_FETCH_FROM_HOSTS_NONE_RESULT;
			break;
	}
}

int QueryBase(char *Content, int ContentLength, int BufferLength, SOCKET ThisSocket)
{
	ControlHeader	*Header = (ControlHeader *)Content;
	char			*RequestEntity = Content + sizeof(ControlHeader);

	int StateOfReceiving = -1;

	/* Check if this domain or type is disabled */
	if( IsDisabledType(Header -> RequestingType) )
	{
		DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_REFUSED);
		ShowRefusingMessage(Header -> Agent, Header -> RequestingType, Header -> RequestingDomain, "Disabled type");
		return QUERY_RESULT_DISABLE;
	}

	if( IsDisabledDomain(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue)) )
	{
		DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_REFUSED);
		ShowRefusingMessage(Header -> Agent, Header -> RequestingType, Header -> RequestingDomain, "Disabled domain");
		return QUERY_RESULT_DISABLE;
	}

	/* Get the QuestionCount */
	if( DNSGetQuestionCount(RequestEntity) == 1 )
	{
		/* First query from hosts and cache */
		StateOfReceiving = DNSFetchFromHosts(Content, ContentLength, BufferLength, ThisSocket);

		if( StateOfReceiving == DNS_FETCH_FROM_HOSTS_NONE_RESULT )
		{
			StateOfReceiving = DNSCache_FetchFromCache(RequestEntity, ContentLength - sizeof(ControlHeader), BufferLength - sizeof(ControlHeader));
			if( StateOfReceiving > 0 )
			{
				ShowNormalMessage(Header -> Agent, Header -> RequestingDomain, RequestEntity, StateOfReceiving, 'C');
				DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_CACHE);
				return StateOfReceiving;
			}
		} else if( StateOfReceiving == DNS_FETCH_FROM_HOSTS_DISABLE_IPV6 )
		{
			DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_REFUSED);
			ShowRefusingMessage(Header -> Agent, Header -> RequestingType, Header -> RequestingDomain, "Disabled by hosts");
			return QUERY_RESULT_DISABLE;
		} else {
			DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_HOSTS);
			if( StateOfReceiving > 0 )
			{
				ShowNormalMessage(Header -> Agent,
									Header -> RequestingDomain,
									RequestEntity,
									StateOfReceiving - sizeof(ControlHeader),
									'H'
									);
				return StateOfReceiving;
			}
		}

	} else {
		StateOfReceiving = -1;
	}

	/* If hosts or cache has no record, then query from server */
	if( StateOfReceiving < 0 )
	{
		StateOfReceiving = QueryFromServer(Content, ContentLength, ThisSocket);
	}

	if( StateOfReceiving < 0 )
	{
		return QUERY_RESULT_ERROR;
	} else {
		return QUERY_RESULT_SUCCESS;
	}
}

int GetMaximumMessageSize(SOCKET sock)
{
#ifdef WIN32
	int		mms = 0;
	int		LengthOfInt = sizeof(mms);

	getsockopt(sock, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&mms, &LengthOfInt);

	return mms;
#else
	return INT_MAX;
#endif
}
