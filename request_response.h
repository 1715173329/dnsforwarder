#ifndef REQUEST_RESPONSE_H_INCLUDED
#define REQUEST_RESPONSE_H_INCLUDED

#include "querydnsbase.h"
#include "readconfig.h"
#include "dnscache.h"
#include "common.h"

int InitAddress(ConfigFileInfo *ConfigInfo);

int InitCheckIPs(ConfigFileInfo *ConfigInfo);

BOOL SocketIsStillReadable(SOCKET Sock, int timeout);

void ClearSocketBuffer(SOCKET Sock);

int SendAndReveiveRawMessageViaTCP(SOCKET			Sock,
								   const void		*Content,
								   int				ContentLength,
								   ExtendableBuffer	*ResultBuffer,
								   uint16_t		*TCPLength /* Big-endian */
								   );

int TCPProxies_Init(StringList *Proxies);

int QueryDNSViaTCP(void);

void SetUDPAntiPollution(BOOL State);

void SetUDPAppendEDNSOpt(BOOL State);

int InitBlockedIP(StringList *l);

int InitIPSubstituting(StringList *l);

int QueryDNSViaUDP(void);

int ProbeFakeAddresses(const char	*ServerAddress,
					   const char	*RequestingDomain,
					   StringList	*out
					   );

struct TestServerArguments
{
	const char *ServerAddress;
	uint32_t *Counter;
};

int TestServer(struct TestServerArguments *Args);

int SetSocketWait(SOCKET sock, BOOL Wait);

int SetSocketSendTimeLimit(SOCKET sock, int time);

int SetSocketRecvTimeLimit(SOCKET sock, int time);

int SetSocketNonBlock(SOCKET sock, BOOL NonBlocked);

BOOL TCPSocketIsHealthy(SOCKET sock);

void CloseTCPConnection(SOCKET sock);

void TransferStart(BOOL StartTCP);

#endif // REQUEST_RESPONSE_H_INCLUDED
