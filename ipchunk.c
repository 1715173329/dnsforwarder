#include <string.h>
#include "ipchunk.h"

static int Compare(IpElement *_1, IpElement *_2)
{
	if( _1 -> IpLength != _2 -> IpLength )
	{
		return  _1 -> IpLength - _2 -> IpLength;
	} else {
		if( _1 -> IpLength == 4 )
		{
			return _1 -> Ip.Ipv4 - _2 -> Ip.Ipv4;
		} else {
			return memcmp(_1 -> Ip.Ipv6, _2 -> Ip.Ipv6, _1 -> IpLength);
		}
	}
}

int IpChunk_Init(IpChunk *ic)
{
	IpElement	Root;
	Root.IpLength = 10;

	if( Bst_Init(&(ic -> Chunk), NULL, sizeof(IpElement), (int (*)(const void *, const void *))Compare) != 0 )
	{
		return -1;
	}

	if( ExtendableBuffer_Init(&(ic -> Datas), 0, -1) != 0 )
	{
        Array_Free(ic -> Chunk.Nodes);
		return -1;
	}

	return Bst_Add(&(ic -> Chunk), &Root);
}

int IpChunk_Add(IpChunk *ic, uint32_t Ip, int Type, const char *Data, uint32_t DataLength)
{
	IpElement	New;
	New.IpLength = 4;
	New.Ip.Ipv4 = Ip;
	New.Type = Type;
	New.DataOffset = -1;

	if( Data != NULL )
	{
		New.DataOffset = ExtendableBuffer_Add(&(ic -> Datas), Data, DataLength);
	}

	return Bst_Add(&(ic -> Chunk), &New);
}

int IpChunk_Add6(IpChunk *ic, const char *Ipv6, int Type, const char *Data, uint32_t DataLength)
{
	IpElement	New;

	New.IpLength = 16;
	memcpy(New.Ip.Ipv6, Ipv6, 16);
	New.Type = Type;
	New.DataOffset = -1;

	if( Data != NULL )
	{
		New.DataOffset = ExtendableBuffer_Add(&(ic -> Datas), Data, DataLength);
	}

	return Bst_Add(&(ic -> Chunk), &New);
}

BOOL IpChunk_Find(IpChunk *ic, uint32_t Ip, int *Type, const char **Data)
{
	IpElement	Key;
	int32_t		Result;

	if( ic == NULL )
	{
		return FALSE;
	}

	Key.IpLength = 4;
	Key.Ip.Ipv4 = Ip;
	Key.Type = 0;
	Key.DataOffset = -1;

	Result = Bst_Search(&(ic -> Chunk), &Key, NULL);

	if( Result < 0 )
	{
		return FALSE;
	} else {
		IpElement *IpResult;

		if( Type != NULL || Data != NULL )
		{
			IpResult = Bst_GetDataByNumber(&(ic -> Chunk), Result);

			if( Type != NULL )
			{
				*Type = IpResult -> Type;
			}

			if( Data != NULL )
			{
				if( IpResult -> DataOffset < 0 )
				{
					*Data = NULL;
				} else {
					*Data = ExtendableBuffer_GetPositionByOffset(&(ic -> Datas), IpResult -> DataOffset);
				}
			}
		}

		return TRUE;
	}
}

BOOL IpChunk_Find6(IpChunk *ic, const char *Ipv6, int *Type, const char **Data)
{
	IpElement	Key;
	int32_t		Result;

	if( ic == NULL )
	{
		return FALSE;
	}

	Key.IpLength = 16;
	memcpy(Key.Ip.Ipv6, Ipv6, 16);
	Key.Type = 0;
	Key.DataOffset = -1;

	Result = Bst_Search(&(ic -> Chunk), &Key, NULL);

	if( Result < 0 )
	{
		return FALSE;
	} else {
		IpElement *IpResult;

		if( Type != NULL || Data != NULL )
		{
			IpResult = Bst_GetDataByNumber(&(ic -> Chunk), Result);

			if( Type != NULL )
			{
				*Type = IpResult -> Type;
			}

			if( Data != NULL )
			{
				if( IpResult -> DataOffset < 0 )
				{
					*Data = NULL;
				} else {
					*Data = ExtendableBuffer_GetPositionByOffset(&(ic -> Datas), IpResult -> DataOffset);
				}
			}
		}

		return TRUE;
	}
}
