#ifndef LINKEDLIST_H_INCLUDED
#define LINKEDLIST_H_INCLUDED

#include "array.h"

typedef struct _ListHead{
	int	Next;
} ListHead;

typedef struct _LinkedQueue{
	int	First;
	int	Last;

	int	FreeList;

	Array	DataList;
} LinkedQueue;

int LinkedQueue_Init(LinkedQueue *l, int DataLength);

int LinkedQueue_Add(LinkedQueue *l, const void *Data);

int LinkedQueue_Get(LinkedQueue *l, void *Buffer);

#endif /* LINKEDLIST */
