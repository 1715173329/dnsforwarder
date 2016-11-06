#include "timedtask.h"
#include "linkedqueue.h"
#include "pipes.h"
#include "debug.h"

typedef struct _TaskInfo{
    TaskFunc    Task;

    void    *Arg1;
    void    *Arg2;

    struct timeval  TimeOut;
    struct timeval  LeftTime;

    BOOL    Persistent;
} TaskInfo;

static LinkedQueue  TimeQueue;

static PIPE_HANDLE  WriteTo, ReadFrom;

static void TimeTask_ReduceTime(const struct timeval *tv)
{
    LinkedQueueIterator i;
    TaskInfo *ti;

    if( tv == NULL )
    {
        /** TODO: Show fatal error */
        return;
    }

    if( LinkedQueueIterator_Init(&i, &TimeQueue) != 0 )
    {
        /** TODO: Show fatal error */
        return;
    }

    while( (ti = i.Next(&i)) != NULL )
    {
        if( ti->LeftTime.tv_usec >= tv->tv_usec )
        {
            ti->LeftTime.tv_usec -= tv->tv_usec;
        } else {
            ti->LeftTime.tv_sec -= 1;
            ti->LeftTime.tv_usec = ti->LeftTime.tv_usec + 1000000 - tv->tv_usec;
        }

        if( ti->LeftTime.tv_sec >= tv->tv_sec )
        {
            ti->LeftTime.tv_sec -= tv->tv_sec;
        } else {
            ti->LeftTime.tv_sec = 0;
        }
    }
}

static int TimeTask_ReallyAdd(TaskInfo *i)
{
    return TimeQueue.Add(&TimeQueue, i);
}

/* Only the particular one thread execute the function */
static void TimeTask_Work(void *Unused)
{
#ifdef WIN32


#else /* WIN32 */
    static fd_set   ReadSet, ReadySet;

    static TaskInfo *i = NULL;
    static struct timeval   *tv = NULL;

    FD_ZERO(&ReadSet);
    FD_SET(ReadFrom, &ReadSet);

    while( TRUE )
    {
        /* Get a task and set the time */
        if( tv == NULL )
        {
            /* Start a new round */
            i = TimeQueue.Get(&TimeQueue);

            if( i == NULL )
            {
                tv = NULL;
            } else {
                tv = &(i->LeftTime);
            }
        } else {
            /* Resume last unfinished round */
        }

        ReadySet = ReadSet;
        switch( select(ReadFrom + 1, &ReadySet, NULL, NULL, tv) )
        {
        case SOCKET_ERROR:
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            ERRORMSG("SOCKET_ERROR Reached, 53.\n");
            while( TRUE )
            {
                SLEEP(32767);
            }
            break;

        case 0:
            /* Run the task */
            TimeTask_ReduceTime(&(i->TimeOut));

            i->Task(i->Arg1, i->Arg2);

            if( i->Persistent )
            {
                i->LeftTime = i->TimeOut;
                if( TimeTask_ReallyAdd(i) != 0 )
                {
                    /** TODO: Show fatal error */
                }
            }

            LinkedQueue_FreeNode(i);
            tv = NULL;
            break;

        default:
            /* Receive a new task from other thread */
            {
                static TaskInfo ni;

                if( READ_PIPE(ReadFrom, &ni, sizeof(TaskInfo)) < 0 )
                {
                    /** TODO: Show fatal error */
                    break;
                }

                if( TimeTask_ReallyAdd(&ni) != 0 )
                {
                    /** TODO: Show fatal error */
                    break;
                }
            }
            break;
        }
    }

#endif /* WIN32 */
}

int TimeTask_Add(BOOL Persistent,
                 int Milliseconds,
                 TaskFunc Func,
                 void *Arg1,
                 void *Arg2
                 )
{
    TaskInfo i;

    if( Func == NULL )
    {
        return -33;
    }

    i.Task = Func;
    i.Arg1 = Arg1;
    i.Arg2 = Arg2;
    i.Persistent = Persistent;
    i.TimeOut.tv_usec = (Milliseconds % 1000) * 1000;
    i.TimeOut.tv_sec = Milliseconds / 1000;
    i.LeftTime = i.TimeOut;

    if( WRITE_PIPE(WriteTo, &i, sizeof(TaskInfo)) < 0 )
    {
        return -53;
    }

    return 0;
}

static int CompareFunc(const void *One, const void *Two)
{
    const TaskInfo *o = One, *t = Two;

    if( o->LeftTime.tv_sec == t->LeftTime.tv_sec )
    {
        return o->LeftTime.tv_usec - t->LeftTime.tv_usec;
    } else {
        return o->LeftTime.tv_sec - t->LeftTime.tv_sec;
    }
}

int TimeTask_Init(void)
{
    ThreadHandle t;

    if( LinkedQueue_Init(&TimeQueue,
                         sizeof(TaskInfo),
                         CompareFunc
                         ) != 0
       )
    {
        return -20;
    }

    if( !CREATE_PIPE_SUCCEEDED(CREATE_PIPE(&ReadFrom, &WriteTo)) )
    {
        return -25;
    }

    CREATE_THREAD(TimeTask_Work, NULL, t);
    DETACH_THREAD(t);

    return 0;
}
