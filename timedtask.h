#ifndef TIMEDTASK_H_INCLUDED
#define TIMEDTASK_H_INCLUDED

#include "common.h"

typedef int (*TaskFunc)(void *Arg1, void *Arg2);

int TimeTask_Init(void);

int TimeTask_Add(BOOL Persistent,
                 int Milliseconds,
                 TaskFunc Func,
                 void *Arg1,
                 void *Arg2
                 );

#endif // TIMEDTASK_H_INCLUDED
