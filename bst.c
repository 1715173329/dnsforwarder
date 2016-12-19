#include <string.h>
#include "bst.h"
#include "utils.h"

#define printf(...)

typedef struct _Bst_NodeHead{
	void	*Parent;
	void	*Left;
	void	*Right;
} Bst_NodeHead;

int Bst_Init(Bst *t, int ElementLength, CompareFunc Compare)
{
	t -> Compare = Compare;
	t -> Root = NULL;
	t -> FreeList = NULL;
	t->ElementLength = ElementLength;

	return StableBuffer_Init(&(t->Nodes));
}

static Bst_NodeHead *GetUnusedNode(Bst *t)
{
    if( t->FreeList == NULL )
    {
        return t->Nodes.Add(&(t->Nodes),
                            NULL,
                            sizeof(Bst_NodeHead) + t->ElementLength,
                            TRUE
                            );
    } else {
        Bst_NodeHead *ret = t->FreeList;

        t->FreeList = ret->Right;

        return ret;
    }
}

static const void *InsertNode(Bst *t,
                              Bst_NodeHead *ParentNode,
                              int CompareResult,
                              const void *Data
                              )
{
    Bst_NodeHead *NewNode = GetUnusedNode(t);

    if( NewNode == NULL )
    {
        return NULL;
    }

    /* Set parent node */
    if( ParentNode == NULL )
    {
        /* Insert as root */
        t->Root = NewNode;
    } else {
        /* Non-root */
        if( CompareResult <= 0 )
        {
            ParentNode->Left = NewNode;
        } else {
            ParentNode->Parent = NewNode;
        }
    }

    /* Set the new child node */
    NewNode->Parent = ParentNode;
    NewNode->Left = NULL;
    NewNode->Right = NULL;

    /* Copy the data */
    memcpy(NewNode + 1, Data, t->ElementLength);

    /* Return the data position */
    return (const void *)(NewNode + 1);

/*
	static const Bst_NodeHead	NewHead = {-1, -1, -1};

	int32_t	NewElement = GetUnusedNode(t);

	if( NewElement >= 0 )
	{
		Bst_NodeHead *NewZone = Array_GetBySubscript(t -> Nodes, NewElement);

		memcpy(NewZone, &NewHead, sizeof(Bst_NodeHead));

        if( ParentNode >= 0 )
        {
            Bst_NodeHead *Parent = Array_GetBySubscript(t -> Nodes, ParentNode);

			NewZone -> Parent = ParentNode;
            if( IsLeft == TRUE )
            {
                Parent -> Left = NewElement;
            } else {
                Parent -> Right = NewElement;
            }

        } else {
			NewZone -> Parent = -1;
            t -> Root = NewElement;
        }

		memcpy(NewZone + 1, Data, t -> Nodes -> DataLength - sizeof(Bst_NodeHead));
		return 0;
	} else {
		return -1;
	}
*/
}

const void *Bst_Add(Bst *t, const void *Data)
{
    if( t -> Root == NULL )
    {
        /* Insert as root */
		return InsertNode(t, NULL, 0, Data);
    } else {
        /* Non-root, finding the currect place to insert */
        Bst_NodeHead *Current = t->Root;

        while( TRUE )
        {
            int CompareResult = (t->Compare)(Data, (const void *)(Current + 1));

            if( CompareResult <= 0 )
            {
                /* Left branch */
                Bst_NodeHead *Left = Current->Left;
                if( Left == NULL )
                {
                    /* Insert here */
                    return InsertNode(t, Current, CompareResult, Data);
                }

                Current = Left;
            } else {
                /* Right branch */
                Bst_NodeHead *Right = Current->Right;
                if( Right == NULL )
                {
                    /* Insert here */
                    return InsertNode(t, Current, CompareResult, Data);
                }

                Current = Right;
            }
        }
    }
/*
		int32_t CurrentNode = t -> Root;

		Bst_NodeHead *Current;

		while( TRUE )
		{
			Current = Array_GetBySubscript(t -> Nodes, CurrentNode);
			if( (t -> Compare)(Data, ((char *)Current) + sizeof(Bst_NodeHead)) <= 0 )
			{
				if( Current -> Left == -1 )
				{

					return Add(t, CurrentNode, TRUE, Data);
				} else {
					CurrentNode = Current -> Left;
				}
			} else {
				if( Current -> Right == -1 )
				{
					return Add(t, CurrentNode, FALSE, Data);
				} else {
					CurrentNode = Current -> Right;
				}
			}
		}
    }
*/
}

const void *Bst_Search(Bst *t, const void *Data, const void *Last)
{
    Bst_NodeHead *Current;

    /* Set the starting point */
    if( Last == NULL )
    {
        /* root as the starting point */
        Current = t->Root;
    } else {
        Current = (((Bst_NodeHead *)Last) - 1)->Left;
    }

    while( Current != NULL )
    {
        int CompareResult = (t->Compare)(Data, (const void *)(Current + 1));

        if( CompareResult == 0 )
        {
            return (const void *)(Current + 1);
        } else if( CompareResult < 0 ){
            Current = Current->Left;
        } else /** CompareResult > 0 */{
            Current = Current->Right;
        }
    }

    return NULL;
/*
	int32_t				CurrentNode;
	const Bst_NodeHead	*Current;
	int					CompareResult;

	printf("\n----------%x-------%s\n", t, __FUNCTION__);

	if( Start == NULL )
	{
		CurrentNode = t -> Root;
	} else {
		const Bst_NodeHead	*Next = (const Bst_NodeHead *)((char *)Start) - sizeof(Bst_NodeHead);

		CurrentNode = Next -> Left;
	}

	while( CurrentNode >= 0 )
	{
		Current = Array_GetBySubscript(t -> Nodes, CurrentNode);
		printf("CurrentNode : %d, Left : %d, Right : %d\n", CurrentNode, Current -> Left, Current -> Right);
		CompareResult = (t -> Compare)(Data, ((char *)Current) + sizeof(Bst_NodeHead));
		printf("CompareResult : %d\n", CompareResult);
		if( CompareResult < 0 )
		{
			CurrentNode = Current -> Left;
		} else if( CompareResult > 0 )
		{
			CurrentNode = Current -> Right;
		} else {
			return CurrentNode;
		}
	}

	return -1;
*/
}

static void Bst_Enum_Inner(Bst *t,
                           Bst_NodeHead *n,
                           Bst_Enum_Callback cb,
                           void *Arg
                           )
{
    if( n == NULL )
    {
        return;
    }

    Bst_Enum_Inner(n->Left);
    cb(t, n + 1, Arg);
    Bst_Enum_Inner(n->Right);
}

void Bst_Enum(Bst *t, Bst_Enum_Callback cb, void *Arg)
{
    Bst_Enum_Inner(t, t->Root, cb, Arg);
}

const void *Bst_Minimum(Bst *t, const void *Subtree)
{
    Bst_NodeHead *Current;

    if( Subtree == NULL )
    {
        /* Starting with the root */
        if( t->Root == NULL )
        {
            /* Empty tree */
            return NULL;
        }

        Current = t->Root;
    } else {
        Current = ((Bst_NodeHead *)Subtree) - 1;
    }

    while( Current->Left != NULL )
    {
        Current = Current->Left;
    }

    return (const void *)(Current + 1);
/*
	int32_t Left = SubTree;
	const Bst_NodeHead	*Node;

	printf("\n----------%x-------%s\n", t, __FUNCTION__);

	while( Left >= 0 )
	{
		Node = Array_GetBySubscript(t -> Nodes, Left);
		printf("CurrentNode : %d, Left : %d, Right : %d\n", Left, Node -> Left, Node -> Right);
		SubTree = Left;
		Left = Node -> Left;
	}

	return SubTree;
*/
}

const void *Bst_Successor(Bst *t, const void *Last)
{
    Bst_NodeHead *Current = ((Bst_NodeHead *)Last) - 1;

    if( Current->Right != NULL )
    {
        return Bst_Minimum(t, (Current->Right) + 1);
    } else {
        Bst_NodeHead *Parent = Current->Parent;

        while( Parent != NULL && Parent->Left != Current )
        {
            Current = Parent;
            Parent = Parent->Parent;
        }

        return Parent == NULL ? NULL : (const void *)(Parent + 1);
    }
/*
	int32_t ParentNum;
	const Bst_NodeHead	*ParentNode;
	const Bst_NodeHead	*Node = Array_GetBySubscript(t -> Nodes, NodeNumber);

	if( Node -> Right >= 0 )
	{
		return Bst_Minimum_ByNumber(t, Node -> Right);
	}

	ParentNum = Node -> Parent;
	while( ParentNum >= 0 )
	{
		ParentNode = Array_GetBySubscript(t -> Nodes, ParentNum);

		if( ParentNode -> Right != NodeNumber )
		{
			break;
		}

		NodeNumber = ParentNum;
		ParentNum = ParentNode -> Parent;
	}

	return ParentNum;
*/
}

void Bst_Delete(Bst *t, const void *Node)
{
    Bst_NodeHead *Current = ((Bst_NodeHead *)Node) - 1;
    Bst_NodeHead *ActuallyRemoved, *Child;

    /* Finding the node that will be actually removed. */
    if( Current->Left == NULL || Current->Right == NULL )
    {
        /* If Current has one or no child */
        ActuallyRemoved = Current;
    } else {
        /* If Current has two child */
        ActuallyRemoved = ((Bst_NodeHead *)Bst_Successor(t, Current + 1)) - 1;
    }

    /* If ActuallyRemoved:
        has two child, impossible case,
        has only one child, get the child,
        or no child, set it to NULL
    */
    if( ActuallyRemoved->Left != NULL )
    {
        Child = ActuallyRemoved->Left;
    } else {
        Child = ActuallyRemoved->Right;
    }

    /* If ActuallyRemoved has one child ( Child != NULL ) */
    if( Child != NULL )
    {
        /* Set the child's parent to its parent's parent */
        Child->Parent = ActuallyRemoved->Parent;
    }

    if( ActuallyRemoved->Parent == NULL )
    {
        /* If ActuallyRemoved is the root */

        t->Root = Child;
    } else {
        /* Or not the root */

        if( ActuallyRemoved->Parent->Left == ActuallyRemoved )
        {
            /* If ActuallyRemoved is a left child */
            ActuallyRemoved->Parent->Left = Child;
        } else {
            /* Or a right child */
            ActuallyRemoved->Parent->Right = Child;
        }
    }

    if( ActuallyRemoved != Current )
    {
        memcpy(Current + 1, ActuallyRemoved + 1, t->ElementLength);
    }

    ActuallyRemoved->Right = t->FreeList;
    t->FreeList = ActuallyRemoved;

    return;
/*
	Bst_NodeHead *Node = Array_GetBySubscript(t -> Nodes, NodeNumber);

	if( t -> PrivateNodes == FALSE )
	{
		return -1;
	}

	printf("\n----------%x-------%s\n", t, __FUNCTION__);
	printf("CurrentNode : %d, Left : %d, Right : %d\n", NodeNumber, Node -> Left, Node -> Right);

	if( Node -> Left < 0 || Node -> Right < 0 )
	{
		int32_t ParentNum = Node -> Parent;
		int32_t ChildNum = -1;

		if( Node -> Right >= 0 )
		{
			ChildNum = Node -> Right;
		} else {
			ChildNum = Node -> Left;
		}

		if( ParentNum < 0 )
		{
			t -> Root = ChildNum;
			if( ChildNum >= 0 )
			{
				Bst_NodeHead *ChildNode = Array_GetBySubscript(t -> Nodes, ChildNum);
				ChildNode -> Parent = -1;
			}
		} else {
			Bst_NodeHead	*ParentNode = Array_GetBySubscript(t -> Nodes, ParentNum);

			printf("ParentNode : %d, Left : %d, Right : %d\n", ParentNum, ParentNode -> Left, ParentNode -> Right);

			if( ParentNode -> Right == NodeNumber )
			{
				ParentNode -> Right = ChildNum;
			} else {
				ParentNode -> Left = ChildNum;
			}

			if( ChildNum >= 0 )
			{
				Bst_NodeHead *ChildNode = Array_GetBySubscript(t -> Nodes, ChildNum);
				ChildNode -> Parent = ParentNum;
			}

			printf("ParentNode : %d, Left : %d, Right : %d\n", ParentNum, ParentNode -> Left, ParentNode -> Right);
		}

		Node -> Parent = -2;
		Node -> Right = t -> FreeList;
		t -> FreeList = NodeNumber;

		printf("CurrentNode : %d, Left : %d, Right : %d\n", NodeNumber, Node -> Left, Node -> Right);
		if( NodeNumber == Node -> Left || NodeNumber == Node -> Right )
		{
			printf("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH\n");
			SLEEP(10000000);
		}

		return NodeNumber;
	} else {
		int32_t DeletedNum = Bst_Delete_ByNumber(t, Bst_Successor_ByNumber(t, NodeNumber));
		Bst_NodeHead *DeletedNode = Array_GetBySubscript(t -> Nodes, DeletedNum);

		memcpy(Node + 1, DeletedNode + 1, t -> Nodes -> DataLength - sizeof(Bst_NodeHead));

        return DeletedNum;
	}
*/
}

int Bst_Reset(Bst *t)
{
	if( !(t->PrivateNodes) )
	{
		return -1;
	}

	Array_Clear(t -> Nodes);
	t -> Root = -1;
	t -> FreeList = -1;

	return 0;
}

void Bst_Free(Bst *t)
{
	if( t->PrivateNodes )
	{
        Array_Free(t->Nodes);
        SafeFree(t->Nodes);
	}
}
