#ifndef _QUERY_DNS_BASE_H_
#define _QUERY_DNS_BASE_H_

#include "logs.h"

typedef enum _DnsQuaryProtocol{
	DNS_QUARY_PROTOCOL_UNSPECIFIED = -1,
	DNS_QUARY_PROTOCOL_UDP = 0,
	DNS_QUARY_PROTOCOL_TCP = 1
} DNSQuaryProtocol;

#include <time.h>
#include "common.h"
#include "dnscache.h"
#include "readconfig.h"

#define QUERY_RESULT_SUCCESS		(0)
#define QUERY_RESULT_DISABLE	(-1)
#define QUERY_RESULT_ERROR		(-2)

int QueryBase(char *Content, int ContentLength, int BufferLength, SOCKET ThisSocket);

int GetHostsByName(const char *Name, const char *Agent, StringList *out);

int GetMaximumMessageSize(SOCKET sock);

#endif /* _QUERY_DNS_BASE_H_ */
