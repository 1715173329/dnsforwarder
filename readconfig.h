#ifndef _READCONFIG_
#define _READCONFIG_

#include <stdio.h>
#include "stringlist.h"
#include "stringchunk.h"
#include "array.h"
#include "common.h"

/* A valid line of a configuration file has the following structure:
 *  <Option> <value>
 * Which `<Option>' is the name of a option, and here we call it `KEY NAME'.
 * And `<value>' is the option's value, we just call it `value'.
 * A line started with `#' is a comment, which will be ignored when it is read.
 * A valid option can be followed a comment which will be ignored too:
 *  <Option> <value> # I'm a comment.
 *
 */

/* Set the max length of a key name */
#define	KEY_NAME_MAX_SIZE	64

/* Set the max length of a option's caption */
#define	CAPTION_MAX_SIZE	128
/* Each option can have a caption, which is a kind of explanatory text. */

/* A value must have a type. Here we just need these three types. */
typedef enum _OptionType{
	TYPE_UNDEFINED = 0,
	TYPE_INT32,
	TYPE_BOOLEAN,
	TYPE_PATH,
	TYPE_STRING
} OptionType;

typedef enum _MultilineStrategy{
	STRATEGY_DEFAULT = 0,
	STRATEGY_REPLACE,
	STRATEGY_APPEND,
	STRATEGY_APPEND_DISCARD_DEFAULT
} MultilineStrategy;

typedef union _VType{
	const char	*str;
	int32_t	INT32;
	BOOL		boolean;
} VType;

typedef enum _OptionStatus{
	STATUS_DEPRECATED = -2,
	STATUS_ALIAS = -1,
	STATUS_UNUSED = 0,
	STATUS_DEFAULT_VALUE,
	STATUS_SPECIAL_VALUE
}OptionStatus;

/* An option */
typedef struct _Option{
	/* Designate if this option is used. */
	OptionStatus	Status;

	MultilineStrategy	Strategy;

	/* Type */
	OptionType	Type;

	/* Value holder */
	union {
		StringList	str;
		int32_t	INT32;
		BOOL		boolean;
	} Holder;

	/* Caption */
	char		*Caption;
} ConfigOption;

/* The exposed type(The infomations about a configuration file) to read options from a configuration file. */
typedef struct _ConfigFileInfo
{
	/* Static, once inited, never changed. */
	FILE	*fp;

	/* An array of all the options. */
	StringChunk	Options;
} ConfigFileInfo;

char *GetKeyNameAndValue(char *Line, const char *Delimiters);

int ConfigInitInfo(ConfigFileInfo *Info);

int ConfigOpenFile(ConfigFileInfo *Info, const char *File);

int ConfigCloseFile(ConfigFileInfo *Info);

int ConfigAddOption(ConfigFileInfo *Info, char *KeyName, MultilineStrategy Strategy, OptionType Type, VType Initial, char *Caption);

int ConfigAddAlias(ConfigFileInfo *Info, char *Alias, char *Target);

int ConfigRead(ConfigFileInfo *Info);

const char *ConfigGetRawString(ConfigFileInfo *Info, char *KeyName);

StringList *ConfigGetStringList(ConfigFileInfo *Info, char *KeyName);

int32_t ConfigGetNumberOfStrings(ConfigFileInfo *Info, char *KeyName);

int32_t ConfigGetInt32(ConfigFileInfo *Info, char *KeyName);

BOOL ConfigGetBoolean(ConfigFileInfo *Info, char *KeyName);

void ConfigSetValue(ConfigFileInfo *Info, VType Value, char *KeyName);

void ConfigDisplay(ConfigFileInfo *Info);

#endif // _READCONFIG_
