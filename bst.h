#ifndef BST_H_INCLUDED
#define BST_H_INCLUDED

#include "stablebuffer.h"
#include "oo.h"

typedef struct _Bst Bst;

typedef int (*Bst_Enum_Callback)(Bst *t, const void *Data, void *Arg);

struct _Bst {
	PRIMEMB StableBuffer    Nodes;
	PRIMEMB int             ElementLength;
	PRIMEMB Bst_NodeHead    *Root;
	PRIMEMB Bst_NodeHead    *FreeList;
	PRIMEMB CompareFunc     Compare;

};

#define	Bst_IsEmpty(t_ptr)	((t_ptr) -> Root == NULL)

#endif // BST_H_INCLUDED
