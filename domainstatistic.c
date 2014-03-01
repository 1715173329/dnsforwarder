#include <stdio.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include "stringchunk.h"
#include "extendablebuffer.h"
#include "domainstatistic.h"
#include "utils.h"
#include "querydnsbase.h"

typedef struct _DomainInfo{
	int		Count;
	int		Refused;
	int		Hosts;
	int		Cache;
	int		Udp;
	int		Tcp;
} DomainInfo;

typedef struct _RankList{
	const char	*Domain;
	int			Count;
} RankList;

static EFFECTIVE_LOCK	StatisticLock;

static StringChunk		MainChunk;

static int				Interval = 0;

static FILE				*MainFile = NULL;

static char				InitTime_Str[32];
static time_t			InitTime_Num;


int DomainStatistic_Init(int OutputInterval)
{
	char FilePath[1024];

	if( OutputInterval < 1 )
	{
		return 1;
	}

	GetFileDirectory(FilePath);
	strcat(FilePath, PATH_SLASH_STR);
	strcat(FilePath, "statistic.txt");

	MainFile = fopen(FilePath, "w");

	if( MainFile == NULL )
	{
		return 2;
	}

	EFFECTIVE_LOCK_INIT(StatisticLock);
	StringChunk_Init(&MainChunk, NULL);

	Interval = OutputInterval * 1000;

	GetCurDateAndTime(InitTime_Str, sizeof(InitTime_Str));
	InitTime_Num = time(NULL);

	return 0;
}

int DomainStatistic_Add(const char *Domain, int *HashValue, StatisticType Type)
{
	DomainInfo *ExistInfo;

	if( Interval == 0 || Domain == NULL )
	{
		return 0;
	}

	EFFECTIVE_LOCK_GET(StatisticLock);

	if( StringChunk_Match(&MainChunk, Domain, HashValue, (char **)&ExistInfo) == FALSE )
	{
		DomainInfo NewInfo;

		memset(&NewInfo, 0, sizeof(DomainInfo));

		NewInfo.Count = 1;

		switch( Type )
		{
			case STATISTIC_TYPE_REFUSED:
				NewInfo.Refused = 1;
				break;

			case STATISTIC_TYPE_HOSTS:
				NewInfo.Hosts = 1;
				break;

			case STATISTIC_TYPE_CACHE:
				NewInfo.Cache = 1;
				break;

			case STATISTIC_TYPE_UDP:
				NewInfo.Udp = 1;
				break;

			case STATISTIC_TYPE_TCP:
				NewInfo.Tcp = 1;
				break;
		}

		StringChunk_Add(&MainChunk, Domain, (const char *)&NewInfo, sizeof(DomainInfo));
	} else {
		if( ExistInfo != NULL )
		{
			++(ExistInfo -> Count);

			switch( Type )
			{
				case STATISTIC_TYPE_REFUSED:
					++(ExistInfo -> Refused);
					break;

				case STATISTIC_TYPE_HOSTS:
					++(ExistInfo -> Hosts);
					break;

				case STATISTIC_TYPE_CACHE:
					++(ExistInfo -> Cache);
					break;

				case STATISTIC_TYPE_UDP:
					++(ExistInfo -> Udp);
					break;

				case STATISTIC_TYPE_TCP:
					++(ExistInfo -> Tcp);
					break;
			}
		}
	}

	EFFECTIVE_LOCK_RELEASE(StatisticLock);

	return 0;
}

static void AddToRankList(RankList *List, int NumberOfInList, const char *CurrentDomain, DomainInfo *DomainInfo)
{
	int Loop;

	int NewPosition = NumberOfInList - 1;

	while( List[NewPosition].Count < DomainInfo -> Count && NewPosition != -1 )
	{
		--NewPosition;
	}

	if( NewPosition == NumberOfInList - 1 )
	{
		return;
	}

	++NewPosition;

	for( Loop = NumberOfInList - 1; Loop != NewPosition; --Loop )
	{
		List[Loop].Domain = List[Loop - 1].Domain;
		List[Loop].Count = List[Loop - 1].Count;
	}

	List[NewPosition].Domain = CurrentDomain;
	List[NewPosition].Count = DomainInfo -> Count;

}

int DomainStatistic_Hold(void)
{
	const char *Str;
	int32_t Enum_Start;

	DomainInfo *Info;

	DomainInfo Sum;
	int	DomainCount;

	#define MAXIMUN_NUMBER_OF_RANKED_DOMAIN 100
	int NumberOfRankedDomain;

	RankList Ranks[MAXIMUN_NUMBER_OF_RANKED_DOMAIN];
	int Loop;

	char GenerateTime_Str[32];
	time_t GenerateTime_Num;

	while(TRUE)
	{
		SLEEP(Interval);

		rewind(MainFile);

		memset(&Sum, 0, sizeof(DomainInfo));

		for( Loop = 0; Loop != MAXIMUN_NUMBER_OF_RANKED_DOMAIN; ++Loop)
		{
			Ranks[Loop].Domain = NULL;
			Ranks[Loop].Count = 0;
		}

		GetCurDateAndTime(GenerateTime_Str, sizeof(GenerateTime_Str));
		GenerateTime_Num = time(NULL);

		fprintf(MainFile,
			    "-----------------------------------------\n"
			    "Program starting time : %s\n"
			    "Last statistic : %s\n"
			    "Elapsed time : %ds\n"
			    "\n"
			    "Domain Statistic:\n"
			    "                                                              Refused\n"
			    "                                                 Domain   Total     | Hosts Cache   UDP   TCP\n",
			InitTime_Str,
			GenerateTime_Str,
			(int)(GenerateTime_Num - InitTime_Num)
			);

		DomainCount = 0;

		Enum_Start = 0;

		EFFECTIVE_LOCK_GET(StatisticLock);

		Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (char **)&Info);

		while( Str != NULL )
		{
			++DomainCount;

			fprintf(MainFile,
					"%55s : %5d %5d %5d %5d %5d %5d\n",
					Str,
					Info -> Count,
					Info -> Refused,
					Info -> Hosts,
					Info -> Cache,
					Info -> Udp,
					Info -> Tcp
					 );

			Sum.Count += Info -> Count;
			Sum.Refused += Info -> Refused;
			Sum.Hosts += Info -> Hosts;
			Sum.Cache += Info -> Cache;
			Sum.Udp += Info -> Udp;
			Sum.Tcp += Info -> Tcp;

			AddToRankList(Ranks, MAXIMUN_NUMBER_OF_RANKED_DOMAIN, Str, Info );

			Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (char **)&Info);

		}

		EFFECTIVE_LOCK_RELEASE(StatisticLock);

		fprintf(MainFile, "Total number of : Queried domains      : %d\n"
						  "                  Requests             : %d\n"
						  "                  Refused&Failed       : %d\n"
						  "                  Responses from hosts : %d\n"
						  "                  Responses from cache : %d\n"
						  "                  Responses via UDP    : %d\n"
						  "                  Responses via TCP    : %d\n",
				DomainCount,
				Sum.Count,
				Sum.Refused,
				Sum.Hosts,
				Sum.Cache,
				Sum.Udp,
				Sum.Tcp
				);

		fprintf(MainFile, "Requests per minute : %.1f\n", (double)Sum.Count / (double)(GenerateTime_Num - InitTime_Num) * 60.0);

		if( Sum.Udp + Sum.Tcp + Sum.Cache != 0 )
		{
			fprintf(MainFile, "Cache utilization : %.1f\n", (double)Sum.Cache / (double)(Sum.Udp + Sum.Tcp + Sum.Cache));
		}

		NumberOfRankedDomain = (DomainCount / 5 + 1) > MAXIMUN_NUMBER_OF_RANKED_DOMAIN ? MAXIMUN_NUMBER_OF_RANKED_DOMAIN : (DomainCount / 5 + 1);

		fprintf(MainFile, "\n%d most frequntely queried domains:\n", NumberOfRankedDomain);

		for( Loop = 0; Loop != NumberOfRankedDomain; ++Loop )
		{
			if( Ranks[Loop].Domain != NULL )
			{
				fprintf(MainFile, "     %s : %d\n", Ranks[Loop].Domain, Ranks[Loop].Count);
			}
		}

		fprintf(MainFile, "\n-----------------------------------------\n");

		fflush(MainFile);
	}

}
