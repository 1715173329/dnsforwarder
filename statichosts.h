#ifndef STATICHOSTS_H_INCLUDED
#define STATICHOSTS_H_INCLUDED

#include "stringchunk.h"
#include "dnsrelated.h"
#include "querydnsbase.h"

#define DOMAIN_NAME_LENGTH_MAX 128

typedef struct _OffsetOfHosts{
	int32_t	Offset;
} OffsetOfHosts;

typedef struct _HostsContainer{
	StringList	Domains;

	StringChunk	Ipv4Hosts;
	StringChunk	Ipv6Hosts;
	StringChunk	CNameHosts;
	StringChunk	ExcludedDomains;
	StringChunk	GoodIpLists;
/*	StringChunk	ExcludedIPs;*/

	ExtendableBuffer	IPs;
} HostsContainer;

extern HostsContainer	MainStaticContainer;

typedef enum _HostsRecordType{
	HOSTS_TYPE_TOO_LONG = -1,

	HOSTS_TYPE_UNKNOWN = 0,

	HOSTS_TYPE_A = 1 << 1,

	HOSTS_TYPE_AAAA = 1 << 2,

	HOSTS_TYPE_CNAME = 1 << 3,

	HOSTS_TYPE_EXCLUEDE = 1 << 4,

	HOSTS_TYPE_CNAME_EXCLUEDE = 1 << 5,

	HOSTS_TYPE_GOOD_IP_LIST = 1 << 6,

} HostsRecordType;

int Hosts_InitContainer(HostsContainer	*Container);

HostsRecordType Hosts_LoadFromMetaLine(HostsContainer *Container, char *MetaLine);

int StaticHosts_Init(ConfigFileInfo *ConfigInfo);

#endif // STATICHOSTS_H_INCLUDED
