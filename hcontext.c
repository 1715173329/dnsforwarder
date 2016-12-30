#include <string.h>
#include <time.h>
#include "hcontext.h"

typedef struct _HostsContextItem HostsContextItem;

struct _HostsContextItem{

    IHeader     oh; /* Original header */
    uint32_t    i; /* Query identifier */
    time_t      t; /* Time of addition */

	char	    RecursedDomain[256];
	int         RecursedHashValue;
};

PUBFUNC int HostsContext_Add(HostsContext    *c,
                             IHeader         *Original, /* Entity followed */
                             const char      *RecursedDomain
                             )
{
    HostsContextItem    n;

    memcpy(&(n.oh), Original, sizeof(IHeader));
    n.i = *(uint16_t *)(Original + 1);
    n.t = time(NULL);

    strncpy(n.RecursedDomain, RecursedDomain, sizeof(n.RecursedDomain));
    n.RecursedDomain[sizeof(n.RecursedDomain) - 1] = '\0';

    n.RecursedHashValue = ELFHash(n.RecursedDomain, 0);

    if( c->t.Add(&(c->t), &n) != NULL )
    {
        return 0;
    } else {
        return -37;
    }
}

PUBFUNC int HostsContext_FindAndRemove(HostsContext *c,

                                       /* Entity followed */
                                       IHeader      *Input,

                                       IHeader      *Output
                                       )
{
    HostsContextItem    k;
    const HostsContextItem *ri;

    k.i = *(uint16_t *)(Input + 1);
    strncpy(k.RecursedDomain, Input->Domain, sizeof(k.RecursedDomain));
    k.RecursedDomain[sizeof(k.RecursedDomain) - 1] = '\0';

    k.RecursedHashValue = Input->HashValue;

    ri = c->t.Search(&(c->t), &k, NULL);
    if( ri == NULL )
    {
        return -55;
    }

    memcpy(Output, &(ri->oh), sizeof(IHeader));

    c->t.Delete(&(c->t), ri);

    return 0;
}

PRIFUNC int HostsContext_Swep_Collect(Bst *t,
                                      const HostsContextItem *Context,
                                      Array *Pending
                                      )
{
    time_t	Now = time(NULL);

    if( Now - Context->t > 2 )
    {
        Array_PushBack(Pending, &Context, NULL);
    }

    return 0;
}


PUBFUNC void HostsContext_Swep(HostsContext *c)
{
    Array Pending;
    int i;

    if( Array_Init(&Pending,
                   sizeof(const HostsContextItem *),
                   4,
                   FALSE,
                   NULL
                   )
       != 0
       )
    {
        return;
    }

    c->t.Enum(&(c->t),
              (Bst_Enum_Callback)HostsContext_Swep_Collect,
              &Pending
              );

    for( i = 0; i < Array_GetUsed(&Pending); ++i )
    {
        const HostsContextItem **Context;

        Context = Array_GetBySubscript(&Pending, i);

        c->t.Delete(&(c->t), *Context);
    }

    Array_Free(&Pending);
}

PRIFUNC int HostsContextCompare(const void *_1, const void *_2)
{
    const HostsContextItem *One = (HostsContextItem *)_1;
    const HostsContextItem *Two = (HostsContextItem *)_2;

	if( One->i != Two->i )
	{
		return (int)(One->i) - (int)(Two->i);
	} else if( One->RecursedHashValue != Two->RecursedHashValue ){
		return One->RecursedHashValue - Two->RecursedHashValue;
	} else {
	    return strcmp(One->RecursedDomain, Two->RecursedDomain);
	}
}

int HostsContext_Init(HostsContext *c)
{
    if( Bst_Init(&(c->t),
                 sizeof(HostsContextItem),
                 (CompareFunc)HostsContextCompare)
       != 0
        )
    {
        return -39;
    }

    c->Add = HostsContext_Add;
    c->FindAndRemove = HostsContext_FindAndRemove;
    c->Swep = HostsContext_Swep;

    return 0;
}
