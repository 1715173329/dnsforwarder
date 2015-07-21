#ifndef CHECKIP_H_INCLUDED
#define CHECKIP_H_INCLUDED

#include "stringchunk.h"

typedef struct _CheckingMeta {
	int Port;
	int Timeout;

	#define	STRATEGY_DISCARD	0
	#define	STRATEGY_KEEP	1
	int Strategy;
} CheckingMeta;

typedef StringChunk	CheckIP;

int CheckIP_Init(CheckIP *c);

int CheckIP_Add(CheckIP *c, const char *Domain, int Port, int Timeout, int Strategy);

int CheckIP_Add_From_String(CheckIP *c, const char *Rule);

const CheckingMeta *CheckIP_Find(CheckIP *c, const char *Domain);
#endif /* CHECKIP_H_INCLUDED */
