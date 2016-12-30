#ifndef HCONTEXT_H_INCLUDED
#define HCONTEXT_H_INCLUDED

#include "bst.h"
#include "iheader.h"
#include "oo.h"

typedef struct _HostsContext HostsContext;

struct _HostsContext
{
    Bst t;

    int (*Add)(HostsContext    *c,
               IHeader         *Original, /* Entity followed */
               const char      *RecursedDomain
               );

    int (*FindAndRemove)(HostsContext *c,

                         /* Entity followed */
                         IHeader      *Input,

                         IHeader      *Output
                         );

    void (*Swep)(HostsContext *c);

};

#endif // HCONTEXT_H_INCLUDED
