#include "hostscontainer.h"
#include "statichosts.h"
#include "logs.h"

static HostsContainer	MainStaticContainer;

HostsContainer *StaticHosts_Init(ConfigFileInfo *ConfigInfo)
{
	StringList *AppendHosts = ConfigGetStringList(ConfigInfo, "AppendHosts");
	StringListIterator  sli;

	const char *Itr;

	if( HostsContainer_Init(&MainStaticContainer) != 0 )
	{
		return NULL;
	}

	if( AppendHosts == NULL )
	{
		return NULL; /* Important */
	}

	if( StringListIterator_Init(&sli, AppendHosts) != 0 )
    {
        return NULL;
    }

	Itr = sli.Next(&sli);
	while( Itr != NULL )
	{
        MainStaticContainer.Load(&MainStaticContainer, Itr);

		Itr = sli.Next(&sli);
	}

	INFO("Loading Appendhosts completed.\n");

	return &MainStaticContainer;
}
