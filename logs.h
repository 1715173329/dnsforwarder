#ifndef LOGS_H_INCLUDED
#define LOGS_H_INCLUDED

#include "readconfig.h"
#include "common.h"
#include "iheader.h"

#define PRINTON		Log_Inited()

#define DEBUGSECTION	if( PRINTON )

int Log_Init(ConfigFileInfo *ConfigInfo, BOOL PrintScreen, BOOL PrintDebug);

BOOL Log_Inited(void);

BOOL Log_DebugOn(void);

void Log_Print(const char *Type, const char *format, ...);

#define	WARNING(...)    Log_Print("WARN", __VA_ARGS__)
#define	INFO(...)       Log_Print("INFO", __VA_ARGS__)
#define	ERRORMSG(...)   Log_Print("ERROR", __VA_ARGS__)
#define	DEBUG(...)      if( Log_DebugOn() ) \
                            Log_Print("DEBUG", __VA_ARGS__);

void ShowRefusingMessage(IHeader *h, const char *Message);

void ShowTimeOutMessage(IHeader *h, char Protocol);

void ShowErrorMessage(IHeader *h, char Protocol);

void ShowNormalMessage(IHeader *h,
                       int PackageLength /* Excluding IHeader */,
                       char Protocol
                       );

void ShowBlockedMessage(IHeader *h,
                        int PackageLength /* Excluding IHeader */,
                        const char *Message
                        );

#endif // LOGS_H_INCLUDED
