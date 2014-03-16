#ifndef _QUERY_DNS_BASE_H_
#define _QUERY_DNS_BASE_H_

#include "debug.h"


#define	PRINT(...)		if(ShowMassages == TRUE){ printf(__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);
#define	INFO(...)		if(ShowMassages == TRUE){ printf("[INFO] "__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);
#define	ERRORMSG(...)	if(ErrorMessages == TRUE){ fprintf(stderr, "[ERROR] "__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);

typedef enum _DnsQuaryProtocol{
	DNS_QUARY_PROTOCOL_UDP = 0,
	DNS_QUARY_PROTOCOL_TCP = 1
} DNSQuaryProtocol;

#include <time.h>
#include "common.h"
#include "dnscache.h"
#include "readconfig.h"
#include "extendablebuffer.h"
#include "internalsocket.h"

/* Global Varibles */
extern ConfigFileInfo	ConfigInfo;
extern BOOL				ShowMassages;
extern BOOL				ErrorMessages;

void ShowRefusingMassage(const char *Agent, DNSRecordType Type, const char *Domain, const char *Massage);

void ShowTimeOutMassage(const char *Agent, DNSRecordType Type, const char *Domain, char Protocol);

void ShowErrorMassage(const char *Agent, DNSRecordType Type, const char *Domain, char ProtocolCharacter);

void ShowNormalMassage(const char *Agent, const char *RequestingDomain, const char *Package, int PackageLength, char ProtocolCharacter);

void ShowBlockedMessage(const char *RequestingDomain, const char *Package, const char *Message);

void ShowFatalMessage(const char *Message, int ErrorCode);

#define QUERY_RESULT_SUCESS		(0)
#define QUERY_RESULT_DISABLE	(-1)
#define QUERY_RESULT_ERROR		(-2)

int QueryBase(char *Content, int ContentLength, int BufferLength, SOCKET ThisSocket);

int GetHostsByRaw(const char *RawPackage, StringList *out);

int GetHostsByName(const char *Name, const char *Agent, StringList *out);

int GetMaximumMessageSize(SOCKET sock);

#endif /* _QUERY_DNS_BASE_H_ */
