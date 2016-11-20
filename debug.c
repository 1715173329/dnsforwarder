#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "debug.h"
#include "utils.h"
#include "common.h"

/* Global Variables */
BOOL			ShowMessages = TRUE;
BOOL			ErrorMessages = TRUE;

static FILE				*Debug_File = NULL;

static int	ThresholdLength = 0;
static int	CurrentLength = 0;
static char	FilePath[1024];


int Debug_Init(ConfigFileInfo *ConfigInfo)
{
	if( ConfigGetBoolean(ConfigInfo, "LogOn") == FALSE )
	{
		return 1;
	}

	sprintf(FilePath, "%s%cdnsforwarder.log", ConfigGetRawString(ConfigInfo, "LogFileFolder"), PATH_SLASH_CH);

	Debug_File = fopen(FilePath, "r+");
	if( Debug_File == NULL )
	{
		Debug_File = fopen(FilePath, "w");
		CurrentLength = 0;
	} else {
		fseek(Debug_File, 0, SEEK_END);
		CurrentLength = ftell(Debug_File);
	}

	ThresholdLength = ConfigGetInt32(ConfigInfo, "LogFileThresholdLength");

	Debug_PrintFile("\n\n\n\n\nNew session\n");

	return 0;
}

BOOL Debug_Inited(void)
{
	return !(Debug_File == NULL);
}

static void CheckLength(void)
{
	if( CurrentLength >= ThresholdLength )
	{
		char FileRenamed[1027];
		int loop;

		fclose(Debug_File);

		for( loop = 1; ; ++loop )
		{
			sprintf(FileRenamed, "%s.%d", FilePath, loop);

			if( FileIsReadable(FileRenamed) == FALSE )
			{
				rename(FilePath, FileRenamed);
				Debug_File = fopen(FilePath, "w");
				CurrentLength = 0;

				break;
			}
		}
	}
}

void Debug_PrintFile(const char *format, ...)
{
	va_list ap;

	if( Debug_Inited() == FALSE )
	{
		return;
	}

	va_start(ap, format);

	CheckLength();

	CurrentLength += vfprintf(Debug_File, format, ap);

	fflush(Debug_File);

	va_end(ap);
}
