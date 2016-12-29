#include "../../bst.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

int f(int *o, int *t)
{
    return *o - *t;
}

int testify(Bst *t, const void *Data, void *Arg)
{
    Bst_NodeHead *n = ((Bst_NodeHead *)Data) - 1;
    Bst_NodeHead *l = n->Left;
    Bst_NodeHead *r = n->Right;

    int in;
    int il = -1;
    int ir = INT_MAX;

    in = *(int *)(n + 1);
    if( l != NULL ) il = *(int *)(l + 1);
    if( r != NULL ) ir = *(int *)(r + 1);

    printf("Node %#010x %d\n", (unsigned int)n, in);

    if( il <= in && ir >= in ){}
    else
        printf("Condition ussatisfied.\n");

    if( (l == NULL && r == NULL) ||
           (l == NULL && r != NULL && r->Parent == n) ||
           (l != NULL && r == NULL && l->Parent == n) ||
           (l != NULL && r != NULL && r->Parent == n && l->Parent == n) ){}
    else
        printf("Parent incorrect.\n");

    return 0;
}

int main(void)
{
    Bst t;
    int i;
    int loop;
    int a;
    const void *Node;

    srand(time(NULL));

    Bst_Init(&t, sizeof(int), f);
/*
    for( loop = 0; loop != 100; ++loop )
    {
        int a;
        i = rand();
        a = *(int *)t.Add(&t, &i);
        printf("i : %d, a : %d\n", i, a);
    }
*/
    i = INT_MAX - 1;
    a = *(int *)t.Add(&t, &i);
    printf("i : %d, a : %d\n", i, a);

    i = INT_MAX - 2;
    a = *(int *)t.Add(&t, &i);
    printf("i : %d, a : %d\n", i, a);

    i = INT_MAX - 3;
    a = *(int *)t.Add(&t, &i);
    printf("i : %d, a : %d\n", i, a);

    i = INT_MAX - 4;
    a = *(int *)t.Add(&t, &i);
    printf("i : %d, a : %d\n", i, a);

    i = INT_MAX - 5;
    a = *(int *)t.Add(&t, &i);
    printf("i : %d, a : %d\n", i, a);
/*
    for( loop = 0; loop != 100; ++loop )
    {
        i = rand();
        a = *(int *)t.Add(&t, &i);
        printf("i : %d, a : %d\n", i, a);
    }
*/
    printf("\n\n");

    t.Enum(&t, testify, NULL);

    printf("\n\n");

    i = INT_MAX - 5;
    Node = t.Search(&t, &i, NULL);
    t.Delete(&t, Node);

    t.Enum(&t, testify, NULL);

    return 0;
}
