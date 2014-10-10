#include <string.h>
#include "gfwlist.h"
#include "querydnsbase.h"
#include "excludedlist.h"
#include "downloader.h"
#include "readline.h"
#include "rwlock.h"
#include "utils.h"

static const char	*GfwList = NULL;
static const char	*File = NULL;

typedef struct _GFWListContainer{
	StringChunk	GFWList;
} GFWListContainer;

static volatile GFWListContainer *MainContainer = NULL;

static RWLock	GFWListLock;

static BOOL ParseGfwListItem(char *Item, GFWListContainer *Container)
{
	char *Itr = NULL;

	if( strchr(Item, '/') != NULL || *Item == '@' || strchr(Item, '?') != NULL || *Item == '!' || strchr(Item, '.') == NULL || *Item == '[' )
	{
		return FALSE;
	}

	if( strchr(Item, '*') != NULL )
	{
		if( strstr("wikipedia.org", Item) == 0 )
		{
			Itr = strchr(Item + 13, '*');
			if( Itr != NULL )
			{
				*Itr = '\0';
			}
		} else {
			return FALSE;
		}
	}

	if( *Item == '|' )
	{
		for(++Item; *Item == '|'; ++Item);
	}

	if( *Item == '.' )
	{
		++Item;
	}

	if( strncmp("http://", Item, 7) == 0 )
	{
		Item += 7;
	}

	if( strncmp("https://", Item, 8) == 0 )
	{
		Item += 8;
	}

	Itr = strchr(Item, '/');
	if( Itr != NULL )
	{
		*Itr = '\0';
	}

	if( strchr(Item, '%') != NULL )
	{
		return FALSE;
	}

	if( MatchDomain(&(Container -> GFWList), Item, NULL) == FALSE )
	{
		StringChunk_Add(&(Container -> GFWList), Item, NULL, 0);
		return TRUE;
	} else {
		return FALSE;
	}

}

static int LoadGfwListFile(const char *File, BOOL NeedBase64Decode)
{
	FILE	*fp;
	ReadLineStatus Status;
	char	Buffer[256];
	int		Count = 0;

	GFWListContainer *Container;

	if( (NeedBase64Decode == TRUE) && (Base64Decode(File) != 0) )
	{
		return -1;
	}

	fp = fopen(File, "r");
	if( fp == NULL )
	{
		return -2;
	}

	Container = SafeMalloc(sizeof(GFWListContainer));
	if( Container == NULL )
	{
		return -3;
	}

	if( StringChunk_Init(&(Container -> GFWList), NULL) != 0 )
	{
		return -4;
	}

	while(TRUE)
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));

		switch(Status)
		{
			case READ_FAILED_OR_END:
				goto DONE;
				break;

			case READ_DONE:
				if( ParseGfwListItem(Buffer, Container) == TRUE )
				{
					++Count;
				}

				break;

			case READ_TRUNCATED:
				INFO("GFWList Item is too long : %s\n", Buffer);
				ReadLine_GoToNextLine(fp);
				break;
		}
	}

DONE:
	fclose(fp);

	if( Count == 0 )
	{
		StringChunk_Free((StringChunk *)&(Container -> GFWList), TRUE);
		SafeFree(Container);
		return -4;
	}

	/* Evict old container */
	RWLock_WrLock(GFWListLock);

	if( MainContainer != NULL )
	{
		StringChunk_Free((StringChunk *)&(MainContainer -> GFWList), TRUE);
		SafeFree((void *)MainContainer);
	}

	MainContainer = Container;

	RWLock_UnWLock(GFWListLock);

	return Count;
}

static int LoadGfwList_Thread(ConfigFileInfo *ConfigInfo)
{
	int		UpdateInterval	=	ConfigGetInt32(ConfigInfo, "GfwListUpdateInterval");
	int		RetryInterval	=	ConfigGetInt32(ConfigInfo, "GfwListRetryInterval");
	BOOL	NeedBase64Decode	=	ConfigGetBoolean(ConfigInfo, "GfwListBase64Decode");
	int		Count;

	if( RetryInterval < 0 )
	{
		RetryInterval = 0;
	}

	while( TRUE )
	{
		INFO("Loading GFW List From %s ...\n", GfwList);
		if( GetFromInternet_Base(GfwList, File) != 0 )
		{
			ERRORMSG("Downloading GFW List failed. Waiting %d second(s) to try again.\n", RetryInterval);
			SLEEP(RetryInterval * 1000);
		} else {
			INFO("GFW List saved at %s.\n", File);

			Count = LoadGfwListFile(File, NeedBase64Decode);

			switch( Count )
			{
				case -1:
				case -2:
				case -3:
					break;

				case -4:
					ERRORMSG("Loading GFW List failed, cannot open file %s. Stop loading.\n", File);
					return -1;
					break;

				default:
					INFO("Loading GFW List completed. %d effective items.\n", Count);
					break;
			}

			if( UpdateInterval < 0 )
			{
				return 0;
			}

			SLEEP(UpdateInterval * 1000);

		}
	}

	return 0;
}

int GfwList_PeriodicWork(ConfigFileInfo *ConfigInfo)
{
	ThreadHandle gt;

	if( GfwList != NULL )
	{
		CREATE_THREAD(LoadGfwList_Thread, ConfigInfo, gt);
		DETACH_THREAD(gt);
	}

	return 0;
}

int GfwList_Init(ConfigFileInfo *ConfigInfo, BOOL StartPeriodWork)
{
	int			Count;

	GfwList	=	ConfigGetRawString(ConfigInfo, "GfwList");

	if( GfwList == NULL )
	{
		return 0;
	}

	File	=	ConfigGetRawString(ConfigInfo, "GfwListDownloadPath");

	RWLock_Init(GFWListLock);

	if( FileIsReadable(File) )
	{
		INFO("Loading the existing GFW List ...\n");

		Count = LoadGfwListFile(File, FALSE);

		switch( Count )
		{
			case -1:
			case -2:
			case -3:
				break;

			case -4:
				ERRORMSG("Loading the existing GFW List failed, cannot open file %s.\n", File);
				break;

			default:
				INFO("Loading the existing GFW List completed. %d effective items.\n", Count);
				break;
		}
	}

	if( StartPeriodWork == TRUE )
	{
		GfwList_PeriodicWork(ConfigInfo);
	}

	return 0;
}

BOOL GfwList_Match(const char *Domain, int *HashValue)
{
	BOOL Result;

	if( MainContainer == NULL )
	{
		return FALSE;
	}

	RWLock_RdLock(GFWListLock);

	Result = MatchDomain((StringChunk *)&(MainContainer -> GFWList), Domain, HashValue);

	RWLock_UnRLock(GFWListLock);

	return Result;
}
