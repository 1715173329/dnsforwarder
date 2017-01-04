#ifndef DYNAMICHOSTS_H_INCLUDED
#define DYNAMICHOSTS_H_INCLUDED

#include "statichosts.h"
#include "querydnsbase.h"
#include "readconfig.h"

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo);

#define HOSTS_TRY_OK			0
#define	HOSTS_TRY_RECURSED		1
#define	HOSTS_TRY_NONE			(-1)
int Hosts_Try(char *Content, int *ContentLength, int BufferLength);

int DynamicHosts_Start(ConfigFileInfo *ConfigInfo);
#endif // DYNAMICHOSTS_H_INCLUDED
