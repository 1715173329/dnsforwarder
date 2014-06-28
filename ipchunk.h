#ifndef IPCHUNK_H_INCLUDED
#define IPCHUNK_H_INCLUDED

#include "bst.h"
#include "extendablebuffer.h"
#include "common.h"

typedef struct _IpElement {
	int			IpLength;
	union {
		uint32_t	Ipv4;
		char		Ipv6[16];
	} Ip;
	int			Type;
	int32_t		DataOffset;
} IpElement;

typedef struct _IpChunk{
	Bst					Chunk;
	ExtendableBuffer	Datas;
} IpChunk;

int IpChunk_Init(IpChunk *ic);

int IpChunk_Add(IpChunk *ic, uint32_t Ip, int Type, const char *Data, uint32_t DataLength);

int IpChunk_Add6(IpChunk *ic, const char *Ipv6, int Type, const char *Data, uint32_t DataLength);

BOOL IpChunk_Find(IpChunk *ic, uint32_t Ip, int *Type, const char **Data);

BOOL IpChunk_Find6(IpChunk *ic, const char *Ipv6, int *Type, const char **Data);


#endif // IPCHUNK_H_INCLUDED
