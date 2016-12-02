#include <time.h>
#include "mcontext.h"
#include "common.h"

typedef struct _ModuleContextItem{
    IHeader     h;
    uint32_t    i; /* Query identifier */
    time_t      t; /* Time of addition */
} ModuleContextItem;

static void ModuleContext_Swep(ModuleContext *c, int TimeOut)
{
	int32_t Start = -1;
	int		Number = 1;

	ModuleContextItem *i;

	time_t	Now = time(NULL);

	i = Bst_Enum(&(c->d), &Start);
	while( i != NULL )
    {
		if( Now - i->t > TimeOut )
		{
            /** TODO: Show timeout message, domain statistic, address advanced */
			Bst_Delete_ByNumber(&(c->d), Start);

			++Number;
		}

		i = Bst_Enum(&(c->d), &Start);
    }
}

static int ModuleContext_Add(ModuleContext *c,
                             IHeader *h /* Entity followed */
                             )
{
    ModuleContextItem n;
    const char *e = (const char *)(h + 1);
    int ret;

    if( h == NULL )
    {
        return -21;
    }

    memcpy(&(n.h), h, sizeof(ModuleContextItem));
    n.i = *(uint16_t *)e;
    n.t = time(NULL);

    ret = Bst_Add(&(c->d), &n);

    if( ret != 0 )
    {
        return 0;
    } else {
        return -83;
    }
}

static int ModuleContext_FindAndRemove(ModuleContext *c,
                                       IHeader *Input, /* Entity followed */
                                       IHeader *Output
                                       )
{
    ModuleContextItem k;
    const char *e = (const char *)(Input + 1);

    int r;
    ModuleContextItem *ri;

    k.i = *(uint16_t *)e;
    k.h.HashValue = Input->HashValue;

    r = Bst_Search(&(c->d), &k, NULL);
    if( r < 0 )
    {
        return -60;
    }

    ri = Bst_GetDataByNumber(&(c->d), r);
    memcpy(Output, &(ri->h), sizeof(IHeader));

    Bst_Delete_ByNumber(&(c->d), r);

    return 0;
}

static int ModuleContextCompare(const void *_1, const void *_2)
{
    const ModuleContextItem *One = (ModuleContextItem *)_1;
    const ModuleContextItem *Two = (ModuleContextItem *)_2;

	if( One->i != Two->i )
	{
		return (int)(One->i) - (int)(Two->i);
	} else {
		return (One->h.HashValue) - (int)(Two->h.HashValue);
	}
}

int ModuleContext_Init(ModuleContext *c)
{
    if( c == NULL )
    {
        return -86;
    }

    if( Bst_Init(&(c->d),
                    NULL,
                    sizeof(ModuleContextItem),
                    ModuleContextCompare
                    )
       != 0
       )
    {
        return -106;
    }

    c->Add = ModuleContext_Add;
    c->FindAndRemove = ModuleContext_FindAndRemove;
    c->Swep = ModuleContext_Swep;

    return 0;
}
