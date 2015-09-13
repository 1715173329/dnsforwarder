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
	int		BlockedMsg;
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
	strcat(FilePath, "statistic.html");

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
	SkipStatistic = FALSE;

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

				case STATISTIC_TYPE_BLOCKEDMSG:
					NewInfo.Count = 0;
					NewInfo.BlockedMsg = 1;
					break;

			}

			StringChunk_Add(&MainChunk, Domain, (const char *)&NewInfo, sizeof(DomainInfo));
		} else {
			if( ExistInfo != NULL )
			{
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

					case STATISTIC_TYPE_BLOCKEDMSG:
						++(ExistInfo -> BlockedMsg);
						break;
				}
			}
		}

	}

	EFFECTIVE_LOCK_RELEASE(StatisticLock);

	return 0;
}

int DomainStatistic_Hold(void)
{
	const char *Str;
	int32_t Enum_Start;

	DomainInfo *Info;

	DomainInfo Sum;
	int	DomainCount;

	char GenerateTime_Str[32];
	time_t GenerateTime_Num;

	while(TRUE)
	{
		SLEEP(Interval);

		rewind(MainFile);

		memset(&Sum, 0, sizeof(DomainInfo));

		GetCurDateAndTime(GenerateTime_Str, sizeof(GenerateTime_Str));
		GenerateTime_Num = time(NULL);

		fprintf(MainFile,
				"<!DOCTYPE html>"
				"<html>"
					"<head>"
						"<title>Domain Statistic</title>"
						"<base target=\"_blank\" />"
					"</head>"
					"<body>"
						"Program startup time : %s</br>"
						"Last statistic : %s</br>"
						"Elapsed time : %ds</br>"
						"</br>"
						"Detials:</br>"
						"<table border=\"1\">"
							"<tr>"
								"<td><h2><a href=\"?sort=domain\" target=\"_self\">Domain</a></h2></td>"
								"<td><h2><a href=\"?sort=total\" target=\"_self\">Total</a></h2></td>"
								"<td><h2><a href=\"?sort=raf\" target=\"_self\">Refused&amp;Failed</a></h2></td>"
								"<td><h2><a href=\"?sort=hosts\" target=\"_self\">Hosts</a></h2></td>"
								"<td><h2><a href=\"?sort=cache\" target=\"_self\">Cache</a></h2></td>"
								"<td><h2><a href=\"?sort=udp\" target=\"_self\">UDP</a></h2></td>"
								"<td><h2><a href=\"?sort=tcp\" target=\"_self\">TCP</a></h2></td>"
								"<td><h2><a href=\"?sort=blockedmsg\" target=\"_self\">BlockedMsg</a></h2></td>"
							"</tr>"
							"<script type=\"text/javascript\">"
								"function GetParameter(name)"
								"{"
									"var Pattern = new RegExp(\"[\\?&]\" + name + \"=[a-z0-9]+\");"
									"var PatternE = Pattern.exec(window.location.href);"

									"if( PatternE != null )"
									"{"
										"return PatternE.toString().split(\"=\")[1];"
									"} else {"
										"return \"total\";"
									"}"
								"}"
								"function InfoSortDomain(i1, i2)"
								"{"
									"return i1.Domain.localeCompare(i2.Domain);"
								"}"
								"function InfoSortTotal(i1, i2)"
								"{"
									"return i2.Total - i1.Total;"
								"}"
								"function InfoSortRaF(i1, i2)"
								"{"
									"return i2.RaF - i1.RaF;"
								"}"
								"function InfoSortHosts(i1, i2)"
								"{"
									"return i2.Hosts - i1.Hosts;"
								"}"
								"function InfoSortCache(i1, i2)"
								"{"
									"return i2.Cache - i1.Cache;"
								"}"
								"function InfoSortUDP(i1, i2)"
								"{"
									"return i2.UDP - i1.UDP;"
								"}"
								"function InfoSortTCP(i1, i2)"
								"{"
									"return i2.TCP - i1.TCP;"
								"}"
								"function InfoSortBlockedMsg(i1, i2)"
								"{"
									"return i2.BlockedMsg- i1.BlockedMsg;"
								"}"

								"var SortFunction;"

								"switch( GetParameter(\"sort\") )"
								"{"
									"case \"domain\":"
										"SortFunction = InfoSortDomain;"
										"break;"
									"case \"total\":"
										"SortFunction = InfoSortTotal;"
										"break;"
									"case \"raf\":"
										"SortFunction = InfoSortRaF;"
										"break;"
									"case \"hosts\":"
										"SortFunction = InfoSortHosts;"
										"break;"
									"case \"cache\":"
										"SortFunction = InfoSortCache;"
										"break;"
									"case \"udp\":"
										"SortFunction = InfoSortUDP;"
										"break;"
									"case \"tcp\":"
										"SortFunction = InfoSortTCP;"
										"break;"
									"case \"blockedmsg\":"
										"SortFunction = InfoSortBlockedMsg;"
										"break;"
								"}"
								"var InfoArray = [",
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

			if( Info != NULL )
			{
				Sum.Count += Info -> Count;
				Sum.Refused += Info -> Refused;
				Sum.Hosts += Info -> Hosts;
				Sum.Cache += Info -> Cache;
				Sum.Udp += Info -> Udp;
				Sum.Tcp += Info -> Tcp;
				Sum.BlockedMsg += Info -> BlockedMsg;

				fprintf(MainFile,
						"{"
							"Domain:\"%s\","
							"Total:%d,"
							"RaF:%d,"
							"Hosts:%d,"
							"Cache:%d,"
							"UDP:%d,"
							"TCP:%d,"
							"BlockedMsg:\"%d\""
						"},",
						Str,
						Info -> Count,
						Info -> Refused,
						Info -> Hosts,
						Info -> Cache,
						Info -> Udp,
						Info -> Tcp,
						Info -> BlockedMsg
						 );
			}

			Str = StringChunk_Enum_NoWildCard(&MainChunk, &Enum_Start, (char **)&Info);
		}

		EFFECTIVE_LOCK_GET(StatisticLock);
		SkipStatistic = FALSE;
		EFFECTIVE_LOCK_RELEASE(StatisticLock);

		fprintf(MainFile,
					"];"
					"InfoArray.sort(SortFunction);"
					"for( var i = 0; i < InfoArray.length; ++i )"
					"{"
						"document.write(\"<tr>\");"
						"document.write(\"<td><a href=http://\" + InfoArray[i].Domain + \">\" + InfoArray[i].Domain + \"</a></td>\");"
						"document.write(\"<td>\" + InfoArray[i].Total + \"</td>\");"
						"document.write(\"<td>\" + InfoArray[i].RaF + \"</td>\");"
						"document.write(\"<td>\" + InfoArray[i].Hosts + \"</td>\");"
						"document.write(\"<td>\" + InfoArray[i].Cache + \"</td>\");"
						"document.write(\"<td>\" + InfoArray[i].UDP + \"</td>\");"
						"document.write(\"<td>\" + InfoArray[i].TCP + \"</td>\");"
						"document.write(\"<td>\" + InfoArray[i].BlockedMsg + \"</td>\");"
						"document.write(\"</tr>\");"
					"}"
				"</script>"
		);

		fprintf(MainFile,
				"<tr>"
					"<td>Sum : %d</td>"
					"<td>%d</td>"
					"<td>%d</td>"
					"<td>%d</td>"
					"<td>%d</td>"
					"<td>%d</td>"
					"<td>%d</td>"
					"<td>%d</td>"
				"</tr>",
				DomainCount,
				Sum.Count,
				Sum.Refused,
				Sum.Hosts,
				Sum.Cache,
				Sum.Udp,
				Sum.Tcp,
				Sum.BlockedMsg
				);

		fprintf(MainFile,		"<tr>"
									"<td><h2>Domain</h2></td>"
									"<td><h2>Total</h2></td>"
									"<td><h2>Refused&amp;Failed</h2></td>"
									"<td><h2>Hosts</h2></td>"
									"<td><h2>Cache</h2></td>"
									"<td><h2>UDP</h2></td>"
									"<td><h2>TCP</h2></td>"
									"<td><h2>BlockedMsg</h2></td>"
								"</tr>"
							"</table>"
				);
		fprintf(MainFile, "</br>Requests per minute : %.1f", (double)Sum.Count / (double)(GenerateTime_Num - InitTime_Num) * 60.0);

		if( Sum.Udp + Sum.Tcp + Sum.Cache != 0 )
		{
			fprintf(MainFile, "</br>Cache utilization : %.1f%%", ((double)Sum.Cache / (double)(Sum.Udp + Sum.Tcp + Sum.Cache)) * 100);
		}

		fprintf(MainFile, "</br></body></html>");

		fflush(MainFile);
	}

}
