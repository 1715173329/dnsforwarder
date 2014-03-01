#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "readconfig.h"
#include "utils.h"
#include "readline.h"

int ConfigInitInfo(ConfigFileInfo *Info)
{
	Info -> fp = NULL;
	Info -> LastAccessedOption = 0;
	return Array_Init(&(Info -> Options), sizeof(ConfigOption), 0, FALSE, NULL);
}

int ConfigOpenFile(ConfigFileInfo *Info, const char *File)
{
	Info -> fp = fopen(File, "r");
	if( Info -> fp == NULL )
		return GET_LAST_ERROR();
	else
		return 0;
}

int ConfigCloseFile(ConfigFileInfo *Info)
{
	return fclose(Info -> fp);
}

int ConfigAddOption(ConfigFileInfo *Info, char *KeyName, MultilineStrategy Strategy, OptionType Type, VType Initial, char *Caption)
{
	ConfigOption New;

	New.KeyName = StringDup(KeyName);
	if( New.KeyName == NULL )
	{
		return -1;
	}

	New.Type = Type;
	New.Status = STATUS_DEFAULT_VALUE;
	New.Strategy = Strategy;

	New.Caption = StringDup(Caption);

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
			if( StringList_Init(&(New.Holder.str), Initial.str, ',') < 0 )
			{
				return 2;
			}

			break;

		default:
			break;
	}

	return Array_PushBack(&(Info -> Options), &New, NULL);
}

int ConfigAddAlias(ConfigFileInfo *Info, char *Alias, char *Target)
{
	ConfigOption New;

	New.KeyName = StringDup(Alias);
	if( New.KeyName == NULL )
	{
		return -1;
	}

	New.Status = STATUS_ALIAS;
	New.Caption = StringDup(Target);

	return Array_PushBack(&(Info -> Options), &New, NULL);
}

static ConfigOption *GetOptionOfAInfo(ConfigFileInfo *Info, const char *KeyName)
{
	int	loop;
	ConfigOption *Option;

	for(loop = Info -> LastAccessedOption; loop != Array_GetUsed(&(Info -> Options)); ++loop)
	{
		Option = Array_GetBySubscript(&(Info -> Options), loop);

		if( Option != NULL && strcmp(KeyName, Option -> KeyName) == 0 )
		{
			Info -> LastAccessedOption = loop;
			if( Option -> Status == STATUS_ALIAS )
			{
				return GetOptionOfAInfo(Info, Option -> Caption);
			} else {
				return Option;
			}
		}
	}

	for(loop = 0; loop != Info -> LastAccessedOption; ++loop)
	{
		Option = Array_GetBySubscript(&(Info -> Options), loop);

		if( Option != NULL && strcmp(KeyName, Option -> KeyName) == 0 )
		{
			Info -> LastAccessedOption = loop;
			if( Option -> Status == STATUS_ALIAS )
			{
				return GetOptionOfAInfo(Info, Option -> Caption);
			} else {
				return Option;
			}
		}
	}

	return NULL;
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

static char *TrimStrings(char *Strings)
{
	char *PrevNonSpace;
	char *NextNonSpace;
	char *Delimiter;

	NextNonSpace = StrNpbrk(Strings, "\t ");
	if( NextNonSpace == NULL )
	{
		return Strings;
	} else {
		if( *NextNonSpace == ',' )
		{
			*Strings = ',';
			NextNonSpace = StrNpbrk(NextNonSpace + 1, "\t ,");
			if( NextNonSpace == NULL )
			{
				*(Strings + 1) = '\0';
				return Strings;
			}

			memmove(Strings + 1, NextNonSpace, strlen(NextNonSpace) + 1);
		} else {
			memmove(Strings, NextNonSpace, strlen(NextNonSpace) + 1);
		}
	}

	Delimiter = strchr(Strings + 1, ',');
    while( Delimiter != NULL )
    {
		PrevNonSpace = GoToPrevNonSpace(Delimiter - 1);
		*(PrevNonSpace + 1) = ',';
		NextNonSpace = StrNpbrk(Delimiter + 1, "\t ,");
		if( NextNonSpace == NULL )
		{
			*(PrevNonSpace + 2) = '\0';
			return Strings;
		} else {
			memmove(PrevNonSpace + 2, NextNonSpace, strlen(NextNonSpace) + 1);
		}

		Delimiter = strchr(PrevNonSpace + 2, ',');
    }

	return Strings;
}

static void ParseBoolean(ConfigOption *Option, char *Value)
{
	switch (Option -> Strategy)
	{
		case STRATEGY_APPEND_DISCARD_DEFAULT:
			if( Option -> Status == STATUS_DEFAULT_VALUE )
			{
				Option -> Strategy = STRATEGY_APPEND;
			}
			/* No break */

		case STRATEGY_DEFAULT:
		case STRATEGY_REPLACE:

			Option -> Holder.boolean = GetBoolealValueFromString(Value);

			Option -> Status = STATUS_SPECIAL_VALUE;
			break;

		case STRATEGY_APPEND:
			{
				BOOL SpecifiedValue;

				SpecifiedValue = GetBoolealValueFromString(Value);
				Option -> Holder.boolean |= SpecifiedValue;

				Option -> Status = STATUS_SPECIAL_VALUE;
			}
			break;

		default:
			break;

	}
}

static void ParseInt32(ConfigOption *Option, const char *Value)
{
	switch (Option -> Strategy)
	{
		case STRATEGY_APPEND_DISCARD_DEFAULT:
			if( Option -> Status == STATUS_DEFAULT_VALUE )
			{
				Option -> Strategy = STRATEGY_APPEND;
			}
			/* No break */

		case STRATEGY_DEFAULT:
		case STRATEGY_REPLACE:
			sscanf(Value, "%d", &(Option -> Holder.INT32));
			Option -> Status = STATUS_SPECIAL_VALUE;
			break;

		case STRATEGY_APPEND:
			{
				int32_t SpecifiedValue;

				sscanf(Value, "%d", &SpecifiedValue);
				Option -> Holder.INT32 += SpecifiedValue;

				Option -> Status = STATUS_SPECIAL_VALUE;
			}
			break;

		default:
			break;
	}
}

static void ParseString(ConfigOption *Option, char *Value, ReadLineStatus ReadStatus, BOOL Trim, FILE *fp, char *Buffer, int BufferLength)
{
	if( Trim == TRUE )
	{
		TrimStrings(Value);
	}

	switch (Option -> Strategy)
	{
		case STRATEGY_APPEND_DISCARD_DEFAULT:
			if( Option -> Status == STATUS_DEFAULT_VALUE )
			{
				Option -> Strategy = STRATEGY_APPEND;
			}
			/* No break */

		case STRATEGY_DEFAULT:
		case STRATEGY_REPLACE:
			StringList_Clear(&(Option -> Holder.str));
			Option -> Status = STATUS_SPECIAL_VALUE;
			if( StringList_Add(&(Option -> Holder.str), Value, ',') < 0 )
			{
				return;
			}

			break;

		case STRATEGY_APPEND:
			if( StringList_Add(&(Option -> Holder.str), Value, ',') < 0 )
			{
				return;
			}
			Option -> Status = STATUS_SPECIAL_VALUE;
			break;

		default:
			return;
			break;
	}

	while( ReadStatus != READ_DONE ){

		ReadStatus = ReadLine(fp, Buffer, BufferLength);
		if( ReadStatus == READ_FAILED_OR_END )
			break;

		if( Trim == TRUE )
		{
			TrimStrings(Value);
		}

		StringList_AppendLast(&(Option -> Holder.str), Buffer, ',');
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

	while(TRUE){
		ReadStatus = ReadLine(Info -> fp, Buffer, sizeof(Buffer));
		if( ReadStatus == READ_FAILED_OR_END )
			return NumOfRead;

		ValuePos = GetKeyNameAndValue(Buffer, " \t=");
		if( ValuePos == NULL )
			continue;

		KeyName = Buffer;

		Option = GetOptionOfAInfo(Info, KeyName);
		if( Option == NULL )
			continue;

		switch( Option -> Type )
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
			case TYPE_STRING:
				ParseString(Option, ValuePos, ReadStatus, TRUE, Info -> fp, Buffer, sizeof(Buffer));
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
		if( Option -> Holder.str.Used == 0 )
		{
			return NULL;
		} else {
			return Option -> Holder.str.Data;
		}
	}

	return NULL;
}

StringList *ConfigGetStringList(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		if( Option -> Holder.str.Used == 0 )
		{
			return NULL;
		} else {
			return &(Option -> Holder.str);
		}
	}

	return NULL;
}

int32_t ConfigGetNumberOfStrings(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return StringList_Count(&(Option -> Holder.str));
	}

	return 0;
}

int32_t ConfigGetInt32(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option -> Holder.INT32;
	}

	return 0;
}

BOOL ConfigGetBoolean(ConfigFileInfo *Info, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		return Option -> Holder.boolean;
	}

	return FALSE;
}

void ConfigSetValue(ConfigFileInfo *Info, VType Value, char *KeyName)
{
	ConfigOption *Option = GetOptionOfAInfo(Info, KeyName);

	if( Option != NULL )
	{
		Option -> Status = STATUS_SPECIAL_VALUE;
		switch( Option -> Type )
		{
			case TYPE_INT32:
				Option -> Holder.INT32 = Value.INT32;
				break;

			case TYPE_BOOLEAN:
				Option -> Holder.boolean = Value.boolean;
				break;

			case TYPE_STRING:
				StringList_Clear(&(Option -> Holder.str));
				StringList_Add(&(Option -> Holder.str), Value.str, ',');
				break;

			default:
				break;
		}
	}
}

void ConfigDisplay(ConfigFileInfo *Info)
{
	int loop;
	ConfigOption *Option;

	for(loop = 0; loop != Array_GetUsed(&(Info -> Options)); ++loop)
	{
		Option = Array_GetBySubscript(&(Info -> Options), loop);

		if( Option != NULL && Option -> Caption != NULL && Option -> Status != STATUS_ALIAS )
		{
			switch( Option -> Type )
			{
				case TYPE_INT32:
					printf("%s:%d\n", Option -> Caption, Option -> Holder.INT32);
					break;

				case TYPE_BOOLEAN:
					printf("%s:%s\n", Option -> Caption, BoolToYesNo(Option -> Holder.boolean));
					break;

				case TYPE_STRING:
					{
						const char *Str = StringList_GetNext(&(Option -> Holder.str), NULL);

						while( Str != NULL )
						{
							printf("%s:%s\n", Option -> Caption, Str);
							Str = StringList_GetNext(&(Option -> Holder.str), Str);
						}
					}
					break;

				default:
					break;
			}
		}
	}
}
