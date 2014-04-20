#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "debug.h"
#include "utils.h"
#include "common.h"

/* Global Variables */
BOOL			ShowMassages = TRUE;
BOOL			ErrorMessages = TRUE;

#ifdef INTERNAL_DEBUG

static EFFECTIVE_LOCK	Debug_Mutex;
static FILE				*Debug_File = NULL;

static int	ThresholdLength = 0;
static int	CurrentLength = 0;
static char	FilePath[1024];


int Debug_Init(int _ThresholdLength)
{
	GetFileDirectory(FilePath);
	strcat(FilePath, PATH_SLASH_STR);
	strcat(FilePath, "Debug.log");

	Debug_File = fopen(FilePath, "r+");
	if( Debug_File == NULL )
	{
		Debug_File = fopen(FilePath, "w");
		CurrentLength = 0;
	} else {
		fseek(Debug_File, 0, SEEK_END);
		CurrentLength = ftell(Debug_File);
	}

	EFFECTIVE_LOCK_INIT(Debug_Mutex);

	ThresholdLength = _ThresholdLength;

	DEBUG_FILE("\n\n\n\n\nNew session\n");
	DEBUG_FILE("CurrentLength : %d\n", CurrentLength);

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

void Debug_PrintFile(const char *Function, int Line, const char *format, ...)
{
	va_list ap;
	char DateAndTime[32];

	if( Debug_Inited() == FALSE )
	{
		return;
	}

	va_start(ap, format);

	EFFECTIVE_LOCK_GET(Debug_Mutex);

	CheckLength();

	GetCurDateAndTime(DateAndTime, sizeof(DateAndTime));

	CurrentLength += fprintf(Debug_File, "T:%d %s:%d %s : ", GET_THREAD_ID(), Function, Line, DateAndTime);
	CurrentLength += vfprintf(Debug_File, format, ap);

	fflush(Debug_File);

	EFFECTIVE_LOCK_RELEASE(Debug_Mutex);

	va_end(ap);
}
#endif
