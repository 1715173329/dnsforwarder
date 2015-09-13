#ifndef DOMAINSTATISTIC_H_INCLUDED
#define DOMAINSTATISTIC_H_INCLUDED

typedef enum _StatisticType{
	STATISTIC_TYPE_REFUSED = 0,
	STATISTIC_TYPE_HOSTS,
	STATISTIC_TYPE_CACHE,
	STATISTIC_TYPE_UDP,
	STATISTIC_TYPE_TCP,

	STATISTIC_TYPE_BLOCKEDMSG
} StatisticType;

int DomainStatistic_Init(int OutputInterval);

int DomainStatistic_Add(const char *Domain, int *HashValue, StatisticType Type);

int DomainStatistic_Hold(void);



#endif // DOMAINSTATISTIC_H_INCLUDED
