#ifndef HOSTS_H_INCLUDED
#define HOSTS_H_INCLUDED

#include "statichosts.h"
#include "querydnsbase.h"
#include "extendablebuffer.h"
#include "readconfig.h"

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo);

#define	MATCH_STATE_PERFECT		0
#define	MATCH_STATE_ONLY_CNAME	1
#define	MATCH_STATE_NONE		(-1)
#define	MATCH_STATE_DISABLED	(-2)
int Hosts_Try(char *Content, int *ContentLength);

int DynamicHosts_Start(ConfigFileInfo *ConfigInfo);
#endif // HOSTS_H_INCLUDED
