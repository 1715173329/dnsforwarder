#ifndef _QUERY_DNS_UDP_H_
#define _QUERY_DNS_UDP_H_

#include "common.h"
#include "readconfig.h"

int QueryDNSListenUDPInit(ConfigFileInfo *ConfigInfo);

void QueryDNSListenUDPStart(void);

#endif /* _QUERY_DNS_UDP_H_ */
