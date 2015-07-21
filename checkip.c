#include <string.h>
#include "checkip.h"
#include "debug.h"

int CheckIP_Init(CheckIP *c)
{
	return StringChunk_Init((StringChunk *)c, NULL);
}

int CheckIP_Add(CheckIP *c, const char *Domain, int Port, int Timeout, int Strategy)
{
	CheckingMeta cm = {Port, Timeout, Strategy};

    return StringChunk_Add_Domain((StringChunk *)c, Domain, (const char *)&cm, sizeof(CheckingMeta));
}

int CheckIP_Add_From_String(CheckIP *c, const char *Rule)
{
	char	Domain[128] = {0}, StrategyS[16] = {0};
	int	Port, Timeout, Strategy;

	sscanf(Rule, "%127s%d%d%15s", Domain, &Port, &Timeout, StrategyS);

	#define IS_STATE(s)	(strncmp(StrategyS, (s), strlen(s)) == 0)
	if( IS_STATE("discard") )
	{
		Strategy = STRATEGY_DISCARD;
	} else if( IS_STATE("keep") ){
		Strategy = STRATEGY_KEEP;
	} else {
		ERRORMSG("Invalid `CheckIP' option : %s\n", Rule);
		return -1;
	}

	return CheckIP_Add(c, Domain, Port, Timeout, Strategy);
}

const CheckingMeta *CheckIP_Find(CheckIP *c, const char *Domain)
{
	const CheckingMeta *cm;

	if( StringChunk_Domain_Match((StringChunk *)c, Domain, NULL, (char **)&cm) == TRUE )
	{
		return cm;
	} else {
		return NULL;
	}
}
