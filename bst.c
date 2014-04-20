#include <string.h>
#include "bst.h"
#include "utils.h"

#define printf(...)

int Bst_Init(Bst *t, Array *Nodes, int ElementLength, int (*Compare)(const void *, const void *))
{
	t -> Compare = Compare;
	t -> Root = -1;
	t -> FreeList = -1;

	if( Nodes == NULL )
	{
		t -> Nodes = (Array *)SafeMalloc(sizeof(Array));
		if( t -> Nodes == NULL )
		{
			return -1;
		}

		return Bst_NodesInit(t -> Nodes, ElementLength);

	} else {
		t -> Nodes = Nodes;

		return 0;
	}
}

int Bst_NodesInit(Array *Nodes, int ElementLength)
{
	return Array_Init(Nodes, ElementLength + sizeof(Bst_NodeHead), 0, FALSE, NULL);
}

static int32_t GetUnusedNode(Bst *t)
{
	if( t -> FreeList >= 0 )
	{
		int32_t ReturnValue = t -> FreeList;
		const Bst_NodeHead *NextNode;

		NextNode = Array_GetBySubscript(t -> Nodes, t -> FreeList);

		t -> FreeList = NextNode -> Right;

		return ReturnValue;
	} else {
		return Array_PushBack(t -> Nodes, NULL, NULL);
	}
}

static int Add(Bst *t, int ParentNode, BOOL IsLeft, const void *Data)
{
	static const Bst_NodeHead	NewHead = {-1, -1, -1};

	int32_t	NewElement = GetUnusedNode(t);
	printf("\n----------%x-------%s\n", t, __FUNCTION__);
	printf("NewElement : %d\n", NewElement);

	if( NewElement >= 0 )
	{
		Bst_NodeHead *NewZone = Array_GetBySubscript(t -> Nodes, NewElement);

		memcpy(NewZone, &NewHead, sizeof(Bst_NodeHead));

        if( ParentNode >= 0 )
        {
            Bst_NodeHead *Parent = Array_GetBySubscript(t -> Nodes, ParentNode);

			NewZone -> Parent = ParentNode;
			printf("Parent : %d, Left : %d, Right : %d\n", ParentNode, Parent -> Left, Parent -> Right);
            if( IsLeft == TRUE )
            {
                Parent -> Left = NewElement;
            } else {
                Parent -> Right = NewElement;
            }
            printf("Parent : %d, Left : %d, Right : %d\n", ParentNode, Parent -> Left, Parent -> Right);
        } else {
			printf("Root : %d\n", t -> Root);
			NewZone -> Parent = -1;
            t -> Root = NewElement;
            printf("Root : %d\n", t -> Root);
        }

		memcpy(NewZone + 1, Data, t -> Nodes -> DataLength - sizeof(Bst_NodeHead));
		return 0;
	} else {
		return -1;
	}
}

int Bst_Add(Bst *t, const void *Data)
{
	printf("\n----------%x-------%s\n", t, __FUNCTION__);

    if( t -> Root == -1 )
    {
		return Add(t, -1, FALSE, Data);
    } else {
		int32_t CurrentNode = t -> Root;

		Bst_NodeHead *Current;

		while( TRUE )
		{
			Current = Array_GetBySubscript(t -> Nodes, CurrentNode);
			printf("CurrentNode : %d, Left : %d, Right : %d\n", CurrentNode, Current -> Left, Current -> Right);
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
					printf("Add to CurrentNode Right.\n");
					return Add(t, CurrentNode, FALSE, Data);
				} else {
					CurrentNode = Current -> Right;
				}
			}
		}
    }
}

int32_t Bst_Search(Bst *t, const void *Data, const void *Start)
{
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
}

void *Bst_Enum(Bst *t, int32_t *Start)
{
	const Bst_NodeHead	*Node;

	if( *Start < 0 )
	{
		*Start = 0;
	} else {
		++(*Start);
	}

	while( TRUE )
	{
		Node = Array_GetBySubscript(t -> Nodes, *Start);
		if( Node == NULL )
		{
			return NULL;
		}

		if( Node -> Parent > -2 )
		{
			return (void *)(Node + 1);
		}

		++(*Start);
	}

}

int32_t Bst_Minimum_ByNumber(Bst *t, int32_t SubTree)
{
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
}

int32_t Bst_Successor_ByNumber(Bst *t, int32_t NodeNumber)
{
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
}

int32_t Bst_Delete_ByNumber(Bst *t, int32_t NodeNumber)
{
	Bst_NodeHead *Node = Array_GetBySubscript(t -> Nodes, NodeNumber);
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
}

void Bst_Reset(Bst *t)
{
	Array_Clear(t -> Nodes);
	t -> Root = -1;
	t -> FreeList = -1;
}
