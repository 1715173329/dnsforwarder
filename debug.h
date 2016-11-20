#ifndef DEBUG_H_INCLUDED
#define DEBUG_H_INCLUDED

#include "readconfig.h"
#include "common.h"

#define	PRINT(...)		if(ShowMessages == TRUE){ printf(__VA_ARGS__); } DEBUG_FILE(__VA_ARGS__);
#define	INFO(...)		if(ShowMessages == TRUE){ printf("[INFO] "__VA_ARGS__); } DEBUG_FILE("[INFO] " __VA_ARGS__);
#define	ERRORMSG(...)	if(ErrorMessages == TRUE){ fprintf(stderr, "[ERROR] "__VA_ARGS__); } DEBUG_FILE("[ERROR] " __VA_ARGS__);

/* Global Varibles */
extern BOOL				ShowMessages;
extern BOOL				ErrorMessages;


#define	DEBUG_FILE(...)	Debug_PrintFile(__VA_ARGS__)

#define	DEBUGP(...)		fprintf(stderr, "[DEBUG] "__VA_ARGS__); \
						DEBUG_FILE(__VA_ARGS__);

#define DEBUGMODE		Debug_Inited()

#define DEBUG	if( DEBUGMODE )

int Debug_Init(ConfigFileInfo *ConfigInfo);

BOOL Debug_Inited(void);

void Debug_PrintFile(const char *format, ...);

#endif // DEBUG_H_INCLUDED
