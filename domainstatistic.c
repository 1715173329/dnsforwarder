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
	int		Poisoned;
} DomainInfo;

typedef struct _RankList{
	const char	*Domain;
	DomainInfo	*Info;
} RankList;

static EFFECTIVE_LOCK	StatisticLock;

static StringChunk		MainChunk;

static int				Interval = 0;

static FILE				*MainFile = NULL;

static char				InitTime_Str[32];
static time_t			InitTime_Num;

volatile static BOOL	SkipStatistic = FALSE;


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

	if( SkipStatistic == FALSE )
	{

		if( StringChunk_Match(&MainChunk, Domain, HashValue, (char **)&ExistInfo) == FALSE )
		{
			DomainInfo NewInfo;

			memset(&NewInfo, 0, sizeof(DomainInfo));

			switch( Type )
			{
				case STATISTIC_TYPE_REFUSED:
					NewInfo.Count = 1;
					NewInfo.Refused = 1;
					break;

				case STATISTIC_TYPE_HOSTS:
					NewInfo.Count = 1;
					NewInfo.Hosts = 1;
					break;

				case STATISTIC_TYPE_CACHE:
					NewInfo.Count = 1;
					NewInfo.Cache = 1;
					break;

				case STATISTIC_TYPE_UDP:
					NewInfo.Count = 1;
					NewInfo.Udp = 1;
					break;

				case STATISTIC_TYPE_TCP:
					NewInfo.Count = 1;
					NewInfo.Tcp = 1;
					break;

				case STATISTIC_TYPE_POISONED:
					NewInfo.Count = 0;
					NewInfo.Poisoned = TRUE;
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
						++(ExistInfo -> Count);
						++(ExistInfo -> Refused);
						break;

					case STATISTIC_TYPE_HOSTS:
						++(ExistInfo -> Count);
						++(ExistInfo -> Hosts);
						break;

					case STATISTIC_TYPE_CACHE:
						++(ExistInfo -> Count);
						++(ExistInfo -> Cache);
						break;

					case STATISTIC_TYPE_UDP:
						++(ExistInfo -> Count);
						++(ExistInfo -> Udp);
						break;

					case STATISTIC_TYPE_TCP:
						++(ExistInfo -> Count);
						++(ExistInfo -> Tcp);
						break;

					case STATISTIC_TYPE_POISONED:
						ExistInfo -> Poisoned = TRUE;
						break;
				}
			}
		}

	}

	EFFECTIVE_LOCK_RELEASE(StatisticLock);

	return 0;
}

static int CountCompare(RankList *_1, RankList *_2)
{
	return (-1) * (_1 -> Info -> Count - _2 -> Info -> Count);
}

int DomainStatistic_Hold(void)
{
	const char *Str;
	int32_t Enum_Start;

	DomainInfo *Info;

	DomainInfo Sum;
	RankList New;
	int	DomainCount;

	RankList *ARank;

	Array Ranks;
	int Loop;

	char GenerateTime_Str[32];
	time_t GenerateTime_Num;

	Array_Init(&Ranks, sizeof(RankList), 0, FALSE, NULL);

	while(TRUE)
	{
		SLEEP(Interval);

		rewind(MainFile);

		memset(&Sum, 0, sizeof(DomainInfo));

		Array_Clear(&Ranks);

		GetCurDateAndTime(GenerateTime_Str, sizeof(GenerateTime_Str));
		GenerateTime_Num = time(NULL);

		fprintf(MainFile,
			    "-----------------------------------------\n"
			    "Program starting time : %s\n"
			    "Last statistic : %s\n"
			    "Elapsed time : %ds\n"
			    "\n"
			    "Domain Statistic:\n"
			    "                                                       Refused&Failed                     Poisoned?\n"
			    "                                                 Domain   Total     | Hosts Cache   UDP   TCP     |\n",
			InitTime_Str,
			GenerateTime_Str,
			(int)(GenerateTime_Num - InitTime_Num)
			);

		DomainCount = 0;

		Enum_Start = 0;

		EFFECTIVE_LOCK_GET(StatisticLock);

		SkipStatistic = TRUE;

		EFFECTIVE_LOCK_RELEASE(StatisticLock);

		Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (char **)&Info);

		while( Str != NULL )
		{
			++DomainCount;

			New.Domain = Str;
			New.Info = Info;

			Array_PushBack(&Ranks, &New, NULL);

			Sum.Count += Info -> Count;
			Sum.Refused += Info -> Refused;
			Sum.Hosts += Info -> Hosts;
			Sum.Cache += Info -> Cache;
			Sum.Udp += Info -> Udp;
			Sum.Tcp += Info -> Tcp;
			Sum.Poisoned += Info -> Poisoned;

			Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (char **)&Info);

		}

		Array_Sort(&Ranks, CountCompare);

		Loop = 0;
		ARank = Array_GetBySubscript(&Ranks, 0);

		while( ARank != NULL )
		{
			fprintf(MainFile,
					"%55s : %5d %5d %5d %5d %5d %5d %s\n",
					ARank -> Domain,
					ARank -> Info -> Count,
					ARank -> Info -> Refused,
					ARank -> Info -> Hosts,
					ARank -> Info -> Cache,
					ARank -> Info -> Udp,
					ARank -> Info -> Tcp,
					ARank -> Info -> Poisoned != FALSE ? "  Yes" : ""
					 );

			++Loop;
			ARank = Array_GetBySubscript(&Ranks, Loop);
		}

		EFFECTIVE_LOCK_GET(StatisticLock);

		SkipStatistic = FALSE;

		EFFECTIVE_LOCK_RELEASE(StatisticLock);

		fprintf(MainFile, "Total number of : Queried domains      : %d\n"
						  "                  Requests             : %d\n"
						  "                  Poisoned domains     : %d\n"
						  "                  Refused&Failed       : %d\n"
						  "                  Responses from hosts : %d\n"
						  "                  Responses from cache : %d\n"
						  "                  Responses via UDP    : %d\n"
						  "                  Responses via TCP    : %d\n",
				DomainCount,
				Sum.Count,
				Sum.Poisoned,
				Sum.Refused,
				Sum.Hosts,
				Sum.Cache,
				Sum.Udp,
				Sum.Tcp
				);

		fprintf(MainFile, "Requests per minute : %.1f\n", (double)Sum.Count / (double)(GenerateTime_Num - InitTime_Num) * 60.0);

		if( Sum.Udp + Sum.Tcp + Sum.Cache != 0 )
		{
			fprintf(MainFile, "Cache utilization : %.1f%%\n", ((double)Sum.Cache / (double)(Sum.Udp + Sum.Tcp + Sum.Cache)) * 100);
		}

		fprintf(MainFile, "\n-----------------------------------------\n");

		fflush(MainFile);
	}

}
