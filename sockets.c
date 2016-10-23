#include "sockets.h"

static int SetSocketWait(SOCKET sock, BOOL Wait)
{
	return setsockopt(sock,
                      SOL_SOCKET,
                      SO_DONTLINGER,
                      (const char *)&Wait,
                      sizeof(BOOL)
                      );
}

SOCKET OpenUDPSocket(sa_family_t Family,
                     struct sockaddr *Address, /* leave NULL if not to bind */
                     BOOL WaitAfterClose
                     )
{
	SOCKET ret = socket(Family, SOCK_DGRAM, IPPROTO_UDP);

	if( ret == INVALID_SOCKET )
	{
		return INVALID_SOCKET;
	}

	if( Address != NULL && bind(ret, Address, GetAddressLength(Family)) != 0 )
	{
		int	OriginalErrorCode;

		OriginalErrorCode = GET_LAST_ERROR();
		CLOSE_SOCKET(ret);
		SET_LAST_ERROR(OriginalErrorCode);

		return INVALID_SOCKET;
	}

	if( !WaitAfterClose )
    {
        SetSocketWait(ret, FALSE);
    }

	return ret;
}
