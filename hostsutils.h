#ifndef HOSTSUTILS_H_INCLUDED
#define HOSTSUTILS_H_INCLUDED

#include "iheader.h"
#include "hostscontainer.h"

#define HOSTS_TRY_OK			0
#define	HOSTS_TRY_RECURSED		1
#define	HOSTS_TRY_NONE			(-1)
int Hosts_Try(IHeader *Header, int BufferLength, HostsContainer *Container);



#endif // HOSTSUTILS_H_INCLUDED
