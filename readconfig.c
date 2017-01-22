#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "readconfig.h"
#include "utils.h"
#include "readline.h"

int ConfigInitInfo(ConfigFileInfo *Info, const char *Contexts)
{
    StringList  l;
	StringListIterator  sli;

    const char  *Itr;
	Info->fp = NULL;

	if( StringChunk_Init(&(Info->Contexts), NULL) != 0 )
    {
        return -1;
    }

    if( StringList_Init(&l, Contexts, ",") != 0 )
    {
    	StringChunk_Free(&(Info->Contexts), TRUE);
        return -2;
    }

	if( StringListIterator_Init(&sli, &l) != 0 )
    {
        StringChunk_Free(&(Info->Contexts), TRUE);
        l.Free(&l);
        return -3;
    }

    Itr = sli.Next(&sli);
    while( Itr != NULL )
    {
        StringChunk_Add(&(Info->Contexts), Itr, NULL, 0);
        Itr = sli.Next(&sli);
    }

    l.Free(&l);

    if( StringChunk_Init(&(Info->Options), NULL) != 0 )
    {
        StringChunk_Free(&(Info->Contexts), TRUE);
        return -4;
    }

	return 0;
}

int ConfigOpenFile(ConfigFileInfo *Info, const char *File)
{
	Info->fp = fopen(File, "r");
	if( Info->fp == NULL )
		return -56;
	else
		return 0;
}

int ConfigCloseFile(ConfigFileInfo *Info)
{
	return fclose(Info->fp);
}

int ConfigAddOption(ConfigFileInfo *Info,
                    char *KeyName,
                    MultilineStrategy Strategy,
                    OptionType Type,
                    VType Initial,
                    char *Caption
                    )
{
	ConfigOption New;

	New.Type = Type;
	New.Status = STATUS_DEFAULT_VALUE;
	New.Strategy = Strategy;

	New.Caption = StringDup(Caption);
	New.Delimiters = ",";

	switch( Type )
	{
		case TYPE_INT32:
			New.Holder.INT32 = Initial.INT32;
			break;

		case TYPE_BOOLEAN:
			New.Holder.boolean = Initial.boolean;
			break;

		case TYPE_PATH:
			New.Strategy = STRATEGY_REPLACE;
		case TYPE_STRING:
			if( StringList_Init(&(New.Holder.str), Initial.str, ",") != 0 )
			{
				return 2;
			}

			break;

		default:
			break;
	}

	return StringChunk_Add(&(Info->Options), KeyName, (const char *)&New, sizeof(ConfigOption));
}

int ConfigAddAlias(ConfigFileInfo *Info, char *Alias, char *Target)
{
	ConfigOption New;

	New.Status = STATUS_ALIAS;
	New.Caption = StringDup(Target);

	return StringChunk_Add(&(Info->Options), Alias, (const char *)&New, sizeof(ConfigOption));
}

static ConfigOption *GetOptionOfAInfo(ConfigFileInfo *Info, const char *KeyName)
{
	ConfigOption *Option;

	if( StringChunk_Match_NoWildCard(&(Info->Options), KeyName, NULL, (void **)&Option) == TRUE )
	{
		if( Option->Status == STATUS_ALIAS )
		{
			return GetOptionOfAInfo(Info, Option->Caption);
		} else {
			return Option;
		}
	} else {
		return NULL;
	}
}

int ConfigSetStringDelimiters(ConfigFileInfo *Info,
                              char *KeyName,
                              const char *Delimiters
                              )
{
    ConfigOption *Option;

    Option = GetOptionOfAInfo(Info, KeyName);
    if( Option == NULL )
    {
        return -147;
    }

    Option->Delimiters = StringDup(Delimiters);

    return 0;
}

char *GetKeyNameAndValue(char *Line, const char *Delimiters)
{
	char *Delimiter = strpbrk(Line, Delimiters);

	if( Delimiter == NULL )
	{
		return NULL;
	}

	*Delimiter = '\0';

	return GoToNextNonSpace(Delimiter + 1);
}

static BOOL GetBoolealValueFromString(char *str)
{
	if( isdigit(*str) )
	{
		if( *str == '0' )
			return FALSE;
		else
			return TRUE;
	} else {
		StrToLower(str);

		if( strstr(str, "false") != NULL )
			return FALSE;
		else if( strstr(str, "true") != NULL )
			return TRUE;

		if( strstr(str, "no") != NULL )
			return FALSE;
		else if( strstr(str, "yes") != NULL )
			return TRUE;
	}

	return FALSE;
}

static void ParseBoolean(ConfigOption *Option, char *Value)
{
	switch (Option->Strategy)
	{
		case STRATEGY_APPEND_DISCARD_DEFAULT:
			if( Option->Status == STATUS_DEFAULT_VALUE )
			{
				Option->Strategy = STRATEGY_APPEND;
			}
			/* No break */

		case STRATEGY_DEFAULT:
		case STRATEGY_REPLACE:

			Option->Holder.boolean = GetBoolealValueFromString(Value);

			Option->Status = STATUS_SPECIAL_VALUE;
			break;

		case STRATEGY_APPEND:
			{
				BOOL SpecifiedValue;

				SpecifiedValue = GetBoolealValueFromString(Value);
				Option->Holder.boolean |= SpecifiedValue;

				Option->Status = STATUS_SPECIAL_VALUE;
			}
			break;

		default:
			break;

	}
}

static void ParseInt32(ConfigOption *Option, const char *Value)
{
	switch (Option->Strategy)
	{
		case STRATEGY_APPEND_DISCARD_DEFAULT:
			if( Option->Status == STATUS_DEFAULT_VALUE )
			{
				Option->Strategy = STRATEGY_APPEND;
			}
			/* No break */

		case STRATEGY_DEFAULT:
		case STRATEGY_REPLACE:
			sscanf(Value, "%d", &(Option->Holder.INT32));
			Option->Status = STATUS_SPECIAL_VALUE;
			break;

		case STRATEGY_APPEND:
			{
				int32_t SpecifiedValue;

				sscanf(Value, "%d", &SpecifiedValue);
				Option->Holder.INT32 += SpecifiedValue;

				Option->Status = STATUS_SPECIAL_VALUE;
			}
			break;

		default:
			break;
	}
}

static void ParseString(ConfigOption *Option,
                        char *Value,
                        ReadLineStatus ReadStatus,
                        BOOL Trim,
                        FILE *fp,
                        char *Buffer,
                        int BufferLength
                        )
{
	switch( Option->Strategy )
	{
		case STRATEGY_APPEND_DISCARD_DEFAULT:
			if( Option->Status == STATUS_DEFAULT_VALUE )
			{
				Option->Strategy = STRATEGY_APPEND;
			}
			/* No break */

		case STRATEGY_DEFAULT:
		case STRATEGY_REPLACE:
			Option->Holder.str.Clear(&(Option->Holder.str));
			/* No break */

		case STRATEGY_APPEND:
			if( Option->Holder.str.Add(&(Option->Holder.str),
                                       Value,
                                       Option->Delimiters
                                       )
                == NULL )
			{
				return;
			}
			Option->Status = STATUS_SPECIAL_VALUE;
			break;

		default:
			return;
			break;
	}

	while( ReadStatus != READ_DONE ){

		ReadStatus = ReadLine(fp, Buffer, BufferLength);
		if( ReadStatus == READ_FAILED_OR_END )
			break;

		Option->Holder.str.AppendLast(&(Option->Holder.str), Buffer, Option->Delimiters);
	}

	if( Trim )
    {
        Option->Holder.str.TrimAll(&(Option->Holder.str), NULL);
    }
}

static char *TrimPath(char *Path)
{
	char *LastCharacter = StrRNpbrk(Path, "\"");
	char *FirstLetter;

	if( LastCharacter != NULL )
	{
		*(LastCharacter + 1) = '\0';

		FirstLetter = StrNpbrk(Path, "\"\t ");
		if( FirstLetter != NULL )
		{
			memmove(Path, FirstLetter, strlen(FirstLetter) + 1);
			return Path;
		} else {
			return NULL;
		}
	} else {
		return NULL;
	}
}

int ConfigRead(ConfigFileInfo *Info)
{
	int				NumOfRead	=	0;

	char			Buffer[2048];
	char			*ValuePos;
	ReadLineStatus	ReadStatus;

	char			*KeyName;
	ConfigOption	*Option;

	char            Context_SkipReading[2048] = {'\0'};

	while(TRUE){
		ReadStatus = ReadLine(Info->fp, Buffer, sizeof(Buffer));
		if( ReadStatus == READ_FAILED_OR_END )
			return NumOfRead;

		if( Context_SkipReading[0] != '\0' )
		{
			if( strcmp(Context_SkipReading, Buffer) != 0 )
			{

			} else {
				Context_SkipReading[0] = '\0';
			}

			continue;
		}

        /* If it is a context begin or end */
        if( Buffer[0] == '{' && StringChunk_Match_NoWildCard(&(Info->Contexts), Buffer + 1, NULL, NULL) == TRUE )
		{
			Context_SkipReading[0] = '}';
			strncpy(Context_SkipReading + 1, Buffer + 1, sizeof(Context_SkipReading) - 1);
			continue;
		}

		if( Buffer[0] == '}' )
		{
			continue;
		}

		ValuePos = GetKeyNameAndValue(Buffer, " \t=");
		if( ValuePos == NULL )
			continue;

		KeyName = Buffer;

		Option = GetOptionOfAInfo(Info, KeyName);
		if( Option == NULL )
			continue;

		switch( Option->Type )
		{
			case TYPE_INT32:
				ParseInt32(Option, ValuePos);
				break;

			case TYPE_BOOLEAN:
				ParseBoolean(Option, ValuePos);
				break;

			case TYPE_PATH:
                if( ReadStatus != READ_DONE )
                {
					break;
                }

                if( TrimPath(ValuePos) == NULL )
                {
					break;
				}

				ExpandPath(ValuePos, sizeof(Buffer) - (ValuePos - Buffer));
				/* No break */

			case TYPE_STRING:
				ParseString(Option, ValuePos, ReadStatus, TRUE, Info->fp, Buffer, sizeof(Buffer));
				break;

			default:
				break;
		}
		++NumOfRead;
	}
	return NumOfRead;
}

const char *ConfigGetRawString(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		StringListIterator  sli;

        if( StringListIterator_Init(&sli, &(Option->Holder.str)) != 0 )
        {
            return NULL;
        }

        return sli.Next(&sli);
	} else {
	    return NULL;
	}
}

StringList *ConfigGetStringList(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		if( Option->Holder.str.Count(&(Option->Holder.str)) == 0 )
		{
			return NULL;
		} else {
			return &(Option->Holder.str);
		}
	} else {
		return NULL;
	}
}

int32_t ConfigGetNumberOfStrings(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option->Holder.str.Count(&(Option->Holder.str));
	} else {
		return 0;
	}
}

int32_t ConfigGetInt32(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option->Holder.INT32;
	} else {
		return 0;
	}
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option->Holder.boolean;
	} else {
		return FALSE;
	}
}

/* Won't change the Option's status */
void ConfigSetDefaultValue(ConfigFileInfo *Info, VType Value, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		switch( Option->Type )
		{
			case TYPE_INT32:
				Option->Holder.INT32 = Value.INT32;
				break;

			case TYPE_BOOLEAN:
				Option->Holder.boolean = Value.boolean;
				break;

			case TYPE_STRING:
				Option->Holder.str.Clear(&(Option->Holder.str));
				Option->Holder.str.Add(&(Option->Holder.str),
                                       Value.str,
                                       Option->Delimiters
                                       );
				break;

			default:
				break;
		}
	}
}

void ConfigDisplay(ConfigFileInfo *Info)
{
	const char *Str;
	int32_t Enum_Start;
	ConfigOption *Option;

	Enum_Start = 0;

	Str = StringChunk_Enum_NoWildCard(&(Info->Options), &Enum_Start, (void **)&Option);
	while( Str != NULL )
	{
		if( Option != NULL && Option->Caption != NULL && Option->Status != STATUS_ALIAS )
		{
			switch( Option->Type )
			{
				case TYPE_INT32:
					printf("%s:%d\n", Option->Caption, Option->Holder.INT32);
					break;

				case TYPE_BOOLEAN:
					printf("%s:%s\n", Option->Caption, BoolToYesNo(Option->Holder.boolean));
					break;

				case TYPE_STRING:
					{
					    StringListIterator  sli;
					    const char *Str;

                        if( StringListIterator_Init(&sli, &(Option->Holder.str))
                           != 0
                           )
                        {
                            break;
                        }

                        Str = sli.Next(&sli);
						while( Str != NULL )
						{
							printf("%s:%s\n", Option->Caption, Str);
							Str = sli.Next(&sli);
						}
					}
					break;

				default:
					break;
			}
		}

		Str = StringChunk_Enum_NoWildCard(&(Info->Options), &Enum_Start, (void **)&Option);
	}
}
