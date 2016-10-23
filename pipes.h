#ifndef PIPES_H_INCLUDED
#define PIPES_H_INCLUDED

#ifdef WIN32
    #include <windows.h>

    #define PIPE_HANDLE HANDLE

    #define CREATE_PIPE(rh_ptr, wh_ptr) CreatePipe((rh_ptr), (wh_ptr), NULL, 0)

    #define CREATE_PIPE_SUCCEEDED(ret) ((ret) != 0)
#else /* WIN32 */
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>

    #define PIPE_HANDLE int

    int CREATE_PIPE(PIPE_HANDLE *rh, PIPE_HANDLE *wh);

    #define CREATE_PIPE_SUCCEEDED(ret) ((ret) == 0)

#endif /* WIN32 */

#endif // PIPES_H_INCLUDED
