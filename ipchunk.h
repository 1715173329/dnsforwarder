#ifndef IPCHUNK_H_INCLUDED
#define IPCHUNK_H_INCLUDED

#include "bst.h"
#include "common.h"

typedef struct _IpElement {
	uint32_t	Ip;
} IpElement;

typedef Bst	IpChunk;

int IpChunk_Init(IpChunk *ic);

int IpChunk_Add(IpChunk *ic, uint32_t Ip);

BOOL IpChunk_Find(IpChunk *ic, uint32_t Ip);


#endif // IPCHUNK_H_INCLUDED
