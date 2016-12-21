#ifndef MCONTEXT_H_INCLUDED
#define MCONTEXT_H_INCLUDED
/** Thread unsafe */

#include "iheader.h"
#include "bst.h"

typedef struct _ModuleContext ModuleContext;

struct _ModuleContext{
    /* private */
    Bst	d;

    /* public */
    int (*Add)(ModuleContext *c,
               IHeader *h /* Entity followed */
               );
    int (*FindAndRemove)(ModuleContext *c,
                         IHeader *Input, /* Entity followed */
                         IHeader *Output
                         );

    void (*Swep)(ModuleContext *c);
};

int ModuleContext_Init(ModuleContext *c);

#endif // MCONTEXT_H_INCLUDED
