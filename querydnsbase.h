#ifndef _QUERY_DNS_BASE_H_
#define _QUERY_DNS_BASE_H_

#include "debug.h"

typedef enum _DnsQuaryProtocol{
	DNS_QUARY_PROTOCOL_UNSPECIFIED = -1,
	DNS_QUARY_PROTOCOL_UDP = 0,
	DNS_QUARY_PROTOCOL_TCP = 1
} DNSQuaryProtocol;

#include <time.h>
#include "common.h"
#include "dnscache.h"
#include "readconfig.h"
#include "internalsocket.h"

void ShowRefusingMessage(const char *Agent, DNSRecordType Type, const char *Domain, const char *Message);

void ShowTimeOutMessage(const char *Agent, DNSRecordType Type, const char *Domain, char Protocol);

void ShowErrorMessage(const char *Agent, DNSRecordType Type, const char *Domain, char ProtocolCharacter);

void ShowNormalMessage(const char *Agent, const char *RequestingDomain, char *Package, int PackageLength, char ProtocolCharacter);

void ShowBlockedMessage(const char *RequestingDomain, char *Package, int PackageLength, const char *Message);

void ShowFatalMessage(const char *Message, int ErrorCode);

#define QUERY_RESULT_SUCCESS		(0)
#define QUERY_RESULT_DISABLE	(-1)
#define QUERY_RESULT_ERROR		(-2)

int QueryBase(char *Content, int ContentLength, int BufferLength, SOCKET ThisSocket);

int GetHostsByName(const char *Name, const char *Agent, StringList *out);

int GetMaximumMessageSize(SOCKET sock);

#endif /* _QUERY_DNS_BASE_H_ */
