#ifndef HOSTSCONTAINER_H_INCLUDED
#define HOSTSCONTAINER_H_INCLUDED

#define DOMAIN_NAME_LENGTH_MAX 128

#include "stringchunk.h"
#include "oo.h"

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

typedef struct _HostsContainer HostsContainer;

struct _HostsContainer{
	PRIMENB StringList	Domains;

	PRIMENB StringChunk	Ipv4Hosts;
	PRIMENB StringChunk	Ipv6Hosts;
	PRIMENB StringChunk	CNameHosts;
	PRIMENB StringChunk	ExcludedDomains;
	PRIMENB StringChunk	GoodIpLists;
/*	PRIMENB StringChunk	ExcludedIPs;*/

	PRIMENB StableBuffer    IPs;

	PUBMENB HostsRecordType (*Load)(HostsContainer *Container,
                                    const char *MetaLine
                                    );

    PUBMENB void (*Free)(HostsContainer *Container);

};

int HostsContainer_Init(HostsContainer *Container);

#endif // HOSTSCONTAINER_H_INCLUDED
