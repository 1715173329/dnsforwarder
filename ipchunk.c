#include "ipchunk.h"

static int Compare(IpElement *_1, IpElement *_2)
{
	return (int)(_1 -> Ip) - (int)(_2 -> Ip);
}

int IpChunk_Init(IpChunk *ic)
{
	return Bst_Init(ic, NULL, sizeof(IpElement), (int (*)(const void *, const void *))Compare);
}

int IpChunk_Add(IpChunk *ic, uint32_t Ip)
{
	IpElement	New = {Ip};
	return Bst_Add(ic, &New);
}

BOOL IpChunk_Find(IpChunk *ic, uint32_t Ip)
{
	IpElement	Key = {Ip};

	if( Bst_Search(ic, &Key, NULL) < 0 )
	{
		return FALSE;
	} else {
		return TRUE;
	}
}


