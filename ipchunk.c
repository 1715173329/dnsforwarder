#include "ipchunk.h"

static int Compare(IpElement *_1, IpElement *_2)
{
	return (int)(_1 -> Ip) - (int)(_2 -> Ip);
}

int IpChunk_Init(IpChunk *ic)
{
	if( Bst_Init(&(ic -> Chunk), NULL, sizeof(IpElement), (int (*)(const void *, const void *))Compare) != 0 )
	{
		return -1;
	}

	if( ExtendableBuffer_Init(&(ic -> Datas), 0, -1) != 0 )
	{
        Array_Free(ic -> Chunk.Nodes);
		return -1;
	}

	return 0;
}

int IpChunk_Add(IpChunk *ic, uint32_t Ip, int Type, const char *Data, uint32_t DataLength)
{
	IpElement	New = {Ip, Type, -1};

	if( Data != NULL )
	{
		New.DataOffset = ExtendableBuffer_Add(&(ic -> Datas), Data, DataLength);
	}

	return Bst_Add(&(ic -> Chunk), &New);
}

BOOL IpChunk_Find(IpChunk *ic, uint32_t Ip, int *Type, const char **Data)
{
	IpElement	Key = {Ip, 0, -1};
	int32_t		Result;

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


