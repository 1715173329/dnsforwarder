#ifndef SOCKETS_H_INCLUDED
#define SOCKETS_H_INCLUDED

#include "common.h"

SOCKET OpenUDPSocket(sa_family_t Family,
                     struct sockaddr *Address, /* leave NULL if not to bind */
                     BOOL WaitAfterClose
                     );

#endif // SOCKETS_H_INCLUDED
