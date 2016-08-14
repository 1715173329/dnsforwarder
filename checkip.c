#include <string.h>
#include "checkip.h"
#include "debug.h"

static int CheckIP_Add(CheckIP *c, const char *Domain, int Port, int Timeout, int Strategy)
{
	CheckingMeta cm = {Port, Timeout, Strategy};

    return StringChunk_Add_Domain(&(c -> Chunk), Domain, (const char *)&cm, sizeof(CheckingMeta));
}

/* Domain Port Timeout [keep|discard]  */
static int CheckIP_Add_From_String(CheckIP *c, const char *Rule)
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

static const CheckingMeta *CheckIP_Find(CheckIP *c, const char *Domain)
{
	const CheckingMeta *cm;

	if( StringChunk_Domain_Match(&(c -> Chunk), Domain, NULL, (char **)&cm) == TRUE )
	{
		return cm;
	} else {
		return NULL;
	}
}

int CheckIP_Init(CheckIP *c)
{
    c -> Add = CheckIP_Add;
    c -> AddFromString = CheckIP_Add_From_String;
    c -> Find = CheckIP_Find;
	return StringChunk_Init(&(c -> Chunk), NULL);
}
