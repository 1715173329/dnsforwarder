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

typedef struct _CheckIP CheckIP;

struct _CheckIP{
    StringChunk	Chunk;

    int (*Add)(CheckIP *self, const char *Domain, int Port, int Timeout, int Strategy);
    int (*AddFromString)(CheckIP *self, const char *Rule);
    const CheckingMeta * (*Find)(CheckIP *self, const char *Domain);
};

int CheckIP_Init(CheckIP *c);
#endif /* CHECKIP_H_INCLUDED */
