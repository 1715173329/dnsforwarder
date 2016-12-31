#ifndef DYNAMICHOSTS_H_INCLUDED
#define DYNAMICHOSTS_H_INCLUDED

#include "statichosts.h"
#include "querydnsbase.h"
#include "readconfig.h"

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo);

#define	MATCH_STATE_PERFECT			0
#define	MATCH_STATE_ONLY_CNAME		1
#define	MATCH_STATE_NONE			(-1)
#define	MATCH_STATE_DISABLED		(-2)
#define	MATCH_STATE_DISABLE_IPV6	(-3)
int Hosts_Try(char *Content, int *ContentLength, int BufferLength);

int DynamicHosts_Start(ConfigFileInfo *ConfigInfo);
#endif // DYNAMICHOSTS_H_INCLUDED
