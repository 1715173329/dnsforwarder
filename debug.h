#ifndef DEBUG_H_INCLUDED
#define DEBUG_H_INCLUDED

#include "readconfig.h"

#define	PRINT(...)		if(ShowMassages == TRUE){ printf(__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);
#define	INFO(...)		if(ShowMassages == TRUE){ printf("[INFO] "__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);
#define	ERRORMSG(...)	if(ErrorMessages == TRUE){ fprintf(stderr, "[ERROR] "__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);

/* Global Varibles */
extern ConfigFileInfo	ConfigInfo;
extern BOOL				ShowMassages;
extern BOOL				ErrorMessages;

#ifdef INTERNAL_DEBUG

#include "common.h"

#define	DEBUG_FILE(...)	Debug_PrintFile(__FUNCTION__, __LINE__, __VA_ARGS__)

#define	DEBUGP(...)		fprintf(stderr, "[DEBUG] "__VA_ARGS__); \
						DEBUG_FILE(__VA_ARGS__);

#define DEBUGMODE	Debug_Inited()

#else
#define	DEBUG_FILE(...)
#define	DEBUGP(...)
#define DEBUGMODE	0
#endif

#define DEBUG	if( DEBUGMODE )

#ifdef INTERNAL_DEBUG

int Debug_Init(int _ThresholdLength);

BOOL Debug_Inited(void);

void Debug_PrintFile(const char *Function, int Line, const char *format, ...);

#else

#define Debug_Init

#endif


#endif // DEBUG_H_INCLUDED
