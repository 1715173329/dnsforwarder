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
#include "excludedlist.h"
#include "gfwlist.h"
#include "stringlist.h"
#include "domainstatistic.h"
#include "request_response.h"

void ShowRefusingMassage(const char *Agent, DNSRecordType Type, const char *Domain, const char *Massage)
{
	char DateAndTime[32];

	if( ShowMassages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));
	}

	if( ShowMassages == TRUE )
	{
		printf("%s[R][%s][%s][%s] %s.\n",
			   DateAndTime,
			   Agent,
			   DNSGetTypeName(Type),
			   Domain,
			   Massage
			   );
	}

	DEBUG_FILE("%s[R][%s][%s][%s] %s.\n",
			   DateAndTime,
			   Agent,
			   DNSGetTypeName(Type),
			   Domain,
			   Massage
			   );
}

void ShowTimeOutMassage(const char *Agent, DNSRecordType Type, const char *Domain, char Protocol)
{
	char DateAndTime[32];

	if( ShowMassages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));
	}

	if( ShowMassages == TRUE )
	{
		printf("%s[%c][%s][%s][%s] Timed out.\n",
			  DateAndTime,
			  Protocol,
			  Agent,
			  DNSGetTypeName(Type),
			  Domain
			  );
	}

	DEBUG_FILE("%s[%c][%s][%s][%s] Timed out.\n",
			  DateAndTime,
			  Protocol,
			  Agent,
			  DNSGetTypeName(Type),
			  Domain
			  );
}

void ShowErrorMassage(const char *Agent, DNSRecordType Type, const char *Domain, char ProtocolCharacter)
{
	char	DateAndTime[32];

	int		ErrorNum = GET_LAST_ERROR();
	char	ErrorMessage[320];

	if( ErrorMessages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		ErrorMessage[0] ='\0';

		GetErrorMsg(ErrorNum, ErrorMessage, sizeof(ErrorMessage));

	}

	if( ErrorMessages == TRUE )
	{
		printf("%s[%c][%s][%s][%s] An error occured : %d : %s .\n",
			   DateAndTime,
			   ProtocolCharacter,
			   Agent,
			   DNSGetTypeName(Type),
			   Domain,
			   ErrorNum,
			   ErrorMessage
			   );
	}

	DEBUG_FILE("%s[%c][%s][%s][%s] An error occured : %d : %s .\n",
			   DateAndTime,
			   ProtocolCharacter,
			   Agent,
			   DNSGetTypeName(Type),
			   Domain,
			   ErrorNum,
			   ErrorMessage
			   );
}

void ShowNormalMassage(const char *Agent, const char *RequestingDomain, const char *Package, int PackageLength, char ProtocolCharacter)
{
	DNSRecordType	Type;

	char DateAndTime[32];
	char InfoBuffer[1024];

	if( ShowMassages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		InfoBuffer[0] = '\0';
		GetAllAnswers(Package, InfoBuffer, sizeof(InfoBuffer));

		Type = (DNSRecordType)DNSGetRecordType(DNSJumpHeader(Package));
	}

	if( ShowMassages == TRUE )
	{
		printf("%s[%c][%s][%s][%s] : %d bytes\n%s",
			  DateAndTime,
			  ProtocolCharacter,
			  Agent,
			  DNSGetTypeName(Type),
			  RequestingDomain,
			  PackageLength,
			  InfoBuffer
			  );
	}

	DEBUG_FILE("%s[%c][%s][%s][%s] : %d bytes\n%s",
			  DateAndTime,
			  ProtocolCharacter,
			  Agent,
			  DNSGetTypeName(Type),
			  RequestingDomain,
			  PackageLength,
			  InfoBuffer
			  );
}

void ShowBlockedMessage(const char *RequestingDomain, const char *Package, const char *Message)
{
	char DateAndTime[32];
	char InfoBuffer[1024];

	if( ShowMassages == TRUE || DEBUGMODE )
	{
		GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

		InfoBuffer[0] = '\0';
		GetAllAnswers(Package, InfoBuffer, sizeof(InfoBuffer));
	}

	if( ShowMassages == TRUE )
	{
		printf("%s[B][%s] %s :\n%s", DateAndTime, RequestingDomain, Message == NULL ? "" : Message, InfoBuffer);
	}

	DEBUG_FILE("%s[B][%s] %s :\n%s", DateAndTime, RequestingDomain, Message == NULL ? "" : Message, InfoBuffer);
}

void ShowFatalMessage(const char *Message, int ErrorCode)
{
	char	ErrorMessage[320];

	ErrorMessage[0] = '\0';

	if( ErrorMessages == TRUE || DEBUGMODE )
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
	if(	IsExcludedDomain(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue)) ||
		GfwList_Match(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue))
		 )
	{
		Interface = INTERNAL_INTERFACE_SECONDARY;
	} else {
		Interface = INTERNAL_INTERFACE_PRIMARY;
	}

	return InternalInterface_SendTo(Interface, ThisSocket, Content, ContentLength);
}

static int DNSFetchFromHosts(char *Content, int ContentLength, SOCKET ThisSocket)
{
	ControlHeader	*Header = (ControlHeader *)Content;

	if( Hosts_Try(Header -> RequestingDomain, Header -> RequestingType) == TRUE )
	{
		return InternalInterface_SendTo(INTERNAL_INTERFACE_HOSTS, ThisSocket, Content, ContentLength);
	} else {
		return -1;
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
		ShowRefusingMassage(Header -> Agent, Header -> RequestingType, Header -> RequestingDomain, "Disabled type");
		return QUERY_RESULT_DISABLE;
	}

	if( IsDisabledDomain(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue)) )
	{
		DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_REFUSED);
		ShowRefusingMassage(Header -> Agent, Header -> RequestingType, Header -> RequestingDomain, "Disabled domain");
		return QUERY_RESULT_DISABLE;
	}

	/* Get the QuestionCount */
	if( DNSGetQuestionCount(RequestEntity) == 1 )
	{
		/* First query from hosts and cache */
		StateOfReceiving = DNSFetchFromHosts(Content, ContentLength, ThisSocket);

		if( StateOfReceiving < 0 )
		{
			StateOfReceiving = DNSCache_FetchFromCache(RequestEntity, ContentLength - sizeof(ControlHeader), BufferLength - sizeof(ControlHeader));
			if( StateOfReceiving > 0 )
			{
				ShowNormalMassage(Header -> Agent, Header -> RequestingDomain, RequestEntity, StateOfReceiving, 'C');
				DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_CACHE);
				return StateOfReceiving;
			}
		} else {
			DomainStatistic_Add(Header -> RequestingDomain, &(Header -> RequestingDomainHashValue), STATISTIC_TYPE_HOSTS);
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
		return QUERY_RESULT_SUCESS;
	}
}

int GetHostsByRaw(const char *RawPackage, StringList *out)
{
	int AnswerCount = DNSGetAnswerCount(RawPackage);

	int loop;
	const char *AnswerRecordPosition;
	const char *DataPos;

	int IpAddressCount = 0;

	char Data[] = "               ";

	for( loop = 1; loop <= AnswerCount; ++loop )
	{
		AnswerRecordPosition = DNSGetAnswerRecordPosition(RawPackage, loop);

		if( DNSGetRecordType(AnswerRecordPosition) == DNS_TYPE_A )
		{
			DataPos = DNSGetResourceDataPos(AnswerRecordPosition);

			DNSParseData(RawPackage, DataPos, 1, Data, sizeof(Data), DNS_RECORD_A, NUM_OF_DNS_RECORD_A, 1);

			StringList_Add(out, Data, ',');

			++IpAddressCount;
		}
	}

	return IpAddressCount;
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
