#include <string.h>
#include "linkedqueue.h"

int LinkedQueue_Init(LinkedQueue *l, int DataLength)
{
	l -> First = -1;
	l -> Last = -1;
	l -> FreeList = -1;
    return Array_Init(&(l -> DataList), DataLength + sizeof(ListHead), 0, FALSE, NULL);
}

int LinkedQueue_Add(LinkedQueue *l, const void *Data)
{
	/* Makeup data */
    char TempZone[Array_GetDataLength(&(l -> DataList))];
    ListHead *h = (ListHead *)TempZone;
    h -> Next = -1;
    memcpy(TempZone + sizeof(ListHead), Data, sizeof(TempZone) - sizeof(ListHead));

    int InsertSubscript = -1;
    ListHead *fn, *en;

	/* Makeup node */
	if( l -> FreeList < 0 )
	{
		/* No free node */
		InsertSubscript = Array_PushBack(&(l -> DataList), TempZone, NULL);
		if( InsertSubscript < 0 )
		{
			return -1;
		}
	} else {
		/* Has free node */
		/* Remove the node from free list */
		InsertSubscript = l -> FreeList;
		fn = (ListHead *)Array_GetBySubscript(&(l -> DataList), InsertSubscript);
		if( fn == NULL )
		{
			return -2;
		}
		l -> FreeList = fn -> Next;

		/* Set the data */
		memcpy(fn, TempZone, sizeof(TempZone));
	}

	/* Insert the node */
	if( l -> Last < 0 )
	{
		/* The list is empty */
        l -> First = InsertSubscript;
        l -> Last = InsertSubscript;
	} else {
		/* The list is not empty */
		en = (ListHead *)Array_GetBySubscript(&(l -> DataList), l -> Last);
		if( en == NULL )
		{
			return -3;
		}
        en -> Next = InsertSubscript;
        l -> Last = InsertSubscript;
	}

	return 0;
}

int LinkedQueue_Get(LinkedQueue *l, void *Buffer)
{
	ListHead *n;
	int	s;

	if( l -> First < 0 )
	{
		return -1;
	}

	/* Get the subscript */
	s = l -> First;

	/* Get the node */
	n = (ListHead *)Array_GetBySubscript(&(l -> DataList), s);
	if( n == NULL )
	{
		return -2;
	}

	/* Remove from list, set the First ptr */
	l -> First = n -> Next;

	/* Copy out data */
	if( Buffer != NULL )
	{
		memcpy(Buffer, (char *)(n + 1), Array_GetDataLength(&(l -> DataList)) - sizeof(ListHead));
	}

	/* Set the Last ptr */
	if( n -> Next < 0 )
	{
		l -> Last = -1;
	}

	/* Insert into freelist */
	n -> Next = l -> FreeList;
	l -> FreeList = s;
	return 0;
}

void LinkedQueue_Free(LinkedQueue *l)
{
	Array_Free(&(l -> DataList));
}
