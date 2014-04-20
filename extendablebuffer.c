#include <string.h>
#include "extendablebuffer.h"
#include "utils.h"

int ExtendableBuffer_Init(ExtendableBuffer *eb, uint32_t InitSize, int32_t GuardSize)
{
	if( eb == NULL )
	{
		return 0;
	}

	if( InitSize == 0 )
	{
		eb -> Data = NULL;
	} else {
		eb -> Data = SafeMalloc(InitSize);
		if( eb -> Data == NULL )
		{
			return -1;
		}
	}

	eb -> InitialSize = InitSize;
	eb -> GuardSize = GuardSize;
	eb -> Allocated = InitSize;
	eb -> Used = 0;
	return 0;
}

BOOL ExtendableBuffer_GuarantyLeft(ExtendableBuffer *eb, uint32_t GuarantiedSize)
{
	if( eb == NULL )
	{
		return FALSE;
	}

	if( eb -> Allocated - eb -> Used >= GuarantiedSize)
	{
		return TRUE;
	} else {
		if( eb -> GuardSize > 0 && eb -> Allocated > eb -> GuardSize )
		{
			return FALSE;
		} else {
			int NewSize = eb -> Allocated + ((eb -> Allocated / 2) > GuarantiedSize ? (eb -> Allocated / 2) : GuarantiedSize);

			if( SafeRealloc((void **)&(eb -> Data), NewSize) != 0 )
			{
				return FALSE;
			} else {
				eb -> Allocated = NewSize;
				return TRUE;
			}
		}
	}
}

char *ExtendableBuffer_Expand(ExtendableBuffer *eb,
							  uint32_t ExpandedSize,
							  int32_t *Offset
							  )
{
	if( ExtendableBuffer_GuarantyLeft(eb, ExpandedSize) == TRUE )
	{
		int OldUsed = eb -> Used;
		if( Offset != NULL )
		{
			*Offset = OldUsed;
		}

		eb -> Used += ExpandedSize;
		return (char *)(eb -> Data + OldUsed);
	} else {
		return NULL;
	}
}

/* Offset returned */
int32_t ExtendableBuffer_Add(ExtendableBuffer *eb, const char *Data, uint32_t DataLength)
{
	volatile char *Here;

	if( eb == NULL )
	{
		return -1;
	}

	Here = ExtendableBuffer_Expand(eb, DataLength, NULL);
	if( Here == NULL )
	{
		return -1;
	}

	memcpy((void *)Here, (const void *)Data, DataLength);

	return (char *)Here - ExtendableBuffer_GetData(eb);
}

char *ExtendableBuffer_Eliminate(ExtendableBuffer *eb, uint32_t Start, uint32_t Length)
{
	if( eb == NULL )
	{
		return NULL;
	}

	memmove((void *)(eb -> Data + Start), (const void *)(eb -> Data + Start + Length), eb -> Used - Start - Length);
	eb -> Used -= Length;
	return (char *)(eb -> Data);
}

void ExtendableBuffer_Reset(ExtendableBuffer *eb)
{
	if( eb != NULL )
	{
		if( eb -> GuardSize > 0 && eb -> Allocated > eb -> GuardSize )
		{
			if( eb -> InitialSize == 0 )
			{
				SafeFree((void *)(eb -> Data));
				eb -> Data = NULL;
			} else {
				if( SafeRealloc((void **)&(eb -> Data), eb -> InitialSize) != 0 )
				{
					return;
				}
			}
			eb -> Allocated = eb -> InitialSize;
		}
		eb -> Used = 0;
	}
}

void ExtendableBuffer_Free(ExtendableBuffer *eb)
{
	if( eb != NULL )
	{
		SafeFree((void *)(eb -> Data));
		eb -> Data = NULL;
	}
}
