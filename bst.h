#ifndef BST_H_INCLUDED
#define BST_H_INCLUDED

#include "array.h"

typedef struct _Bst_NodeHead{
	int32_t	Parent;
	int32_t	Left;
	int32_t	Right;
} Bst_NodeHead;

typedef struct _Bst {
	Array	*Nodes;
	BOOL    PrivateNodes;

	int32_t	Root;

	int32_t FreeList;

	int		(*Compare)(const void *, const void *);
} Bst;

int Bst_Init(Bst *t, Array *Nodes, int ElementLength, int (*Compare)(const void *, const void *));

int Bst_NodesInit(Array *Nodes, int ElementLength);

int Bst_Add(Bst *t, const void *Data);

#define	Bst_IsEmpty(t_ptr)	((t_ptr) -> Root == -1)

int32_t Bst_Search(Bst *t, const void *Data, const void *Start);

void *Bst_Enum(Bst *t, int32_t *Start);

#define	Bst_GetDataByNumber(t_ptr, number) (void *)(((Bst_NodeHead *)Array_GetBySubscript((t_ptr) -> Nodes, (number))) + 1)

int32_t Bst_Minimum_ByNumber(Bst *t, int32_t SubTree);

int32_t Bst_Successor_ByNumber(Bst *t, int32_t NodeNumber);

int32_t Bst_Delete_ByNumber(Bst *t, int32_t NodeNumber);

int Bst_Reset(Bst *t);

#endif // BST_H_INCLUDED
