#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "dynamichosts.h"
#include "dnsrelated.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "goodiplist.h"
#include "timedtask.h"
#include "hcontext.h"
#include "udpfrontend.h"
#include "socketpuller.h"
#include "rwlock.h"

static HostsContainer   *MainStaticContainer = NULL;
static BOOL			DisableIpv6WhenIpv4Exists = FALSE;
static const char 	*File = NULL;
static RWLock		HostsLock;
static volatile HostsContainer	*MainDynamicContainer = NULL;

static int DynamicHosts_Load(void)
{
	FILE			*fp;
	char			Buffer[320];
	ReadLineStatus	Status;

	HostsContainer *TempContainer;

	fp = fopen(File, "r");
	if( fp == NULL )
	{
		return -1;
	}

	TempContainer = (HostsContainer *)SafeMalloc(sizeof(HostsContainer));
	if( TempContainer == NULL )
	{
		fclose(fp);
		return -1;
	}

	if( HostsContainer_Init(TempContainer) != 0 )
	{
		fclose(fp);

		SafeFree(TempContainer);
		return -1;
	}

	while( TRUE )
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));
		if( Status == READ_FAILED_OR_END )
        {
            ERRORMSG("Loading hosts failed.\n", Buffer);
            fclose(fp);
            TempContainer->Free(TempContainer);
            SafeFree(TempContainer);
            return -66;
        }

		if( Status == READ_TRUNCATED )
		{
			ERRORMSG("Hosts is too long : %s\n", Buffer);
			ReadLine_GoToNextLine(fp);
			continue;
		}

        TempContainer->Load(TempContainer, Buffer)
	}

	RWLock_WrLock(HostsLock);
	if( MainDynamicContainer != NULL )
	{
	    MainDynamicContainer->Free(MainDynamicContainer);
		SafeFree((void *)MainDynamicContainer);
	}
	MainDynamicContainer = TempContainer;

	RWLock_UnWLock(HostsLock);

	INFO("Loading hosts completed.\n");

	fclose(fp);
	return 0;
}

/* Arguments for updating  */
static int          HostsRetryInterval;
static const char   *Script;
static const char	**HostsURLs;

static void GetHostsFromInternet_Failed(int ErrorCode, const char *URL, const char *File1)
{
	ERRORMSG("Getting Hosts %s failed. Waiting %d second(s) to try again.\n",
             URL,
             HostsRetryInterval
             );
}

static void GetHostsFromInternet_Succeed(const char *URL, const char *File1)
{
	INFO("Hosts %s saved.\n", URL);
}

static void GetHostsFromInternet_Thread(void *Unused1, void *Unused2)
{
	int			DownloadState;

    if( HostsURLs[1] == NULL )
    {
        INFO("Getting hosts from %s ...\n", HostsURLs[0]);
    } else {
        INFO("Getting hosts from various places ...\n");
    }

    DownloadState = GetFromInternet_MultiFiles(HostsURLs,
                                               File,
                                               HostsRetryInterval,
                                               -1,
                                               GetHostsFromInternet_Failed,
                                               GetHostsFromInternet_Succeed
                                               );

    if( DownloadState == 0 )
    {
        INFO("Hosts saved at %s.\n", File);

        if( Script != NULL )
        {
            INFO("Running script ...\n");
            system(Script);
        }

        DynamicHosts_Load();
    } else {
        ERRORMSG("Getting hosts file(s) failed.\n");
    }
}

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo)
{
	StringList  *Hosts;
	int          UpdateInterval;

	MainStaticContainer = StaticHosts_Init(ConfigInfo);

	DisableIpv6WhenIpv4Exists = ConfigGetBoolean(ConfigInfo,
                                                 "DisableIpv6WhenIpv4Exists"
                                                 );

	Hosts = ConfigGetStringList(ConfigInfo, "Hosts");
	if( Path == NULL )
	{
		File = NULL;
		return 0;
	}

    HostsURLs = Hosts->ToCharPtrArray(Hosts);
	UpdateInterval = ConfigGetInt32(ConfigInfo, "HostsUpdateInterval");
	HostsRetryInterval = ConfigGetInt32(ConfigInfo, "HostsRetryInterval");
	Script = ConfigGetRawString(ConfigInfo, "HostsScript");

	RWLock_Init(HostsLock);

	File = ConfigGetRawString(ConfigInfo, "HostsDownloadPath");

	if( HostsRetryInterval < 0 )
	{
		ERRORMSG("`HostsRetryInterval' is too small (< 0).\n");
		File = NULL;
		return 1;
	}

	INFO("Local hosts file : \"%s\"\n", File);

	if( FileIsReadable(File) )
	{
		INFO("Loading the existing hosts file ...\n");
		DynamicHosts_Load();
	} else {
		INFO("Hosts file is unreadable, this may cause some failures.\n");
	}

	if( UpdateInterval <= 0 )
    {
        TimedTask_Add(FALSE,
                      TRUE,
                      0,
                      GetHostsFromInternet_Thread,
                      NULL,
                      NULL,
                      TRUE);
    } else {
        TimedTask_Add(TRUE,
                      TRUE,
                      UpdateInterval,
                      GetHostsFromInternet_Thread,
                      NULL,
                      NULL,
                      TRUE);
    }

	return 0;
}

int DynamicHosts_Start(ConfigFileInfo *ConfigInfo)
{
	if( StaticHostsInited == TRUE || File != NULL )
	{
		CREATE_THREAD(DynamicHosts_SocketLoop, NULL, t);
		DETACH_THREAD(t);
	}

	return 0;
}

int DynamicHosts_SocketLoop(void)
{
	static uint16_t	NewIdentifier;

	static HostsContext	Context;
	static SocketPuller Puller;

    static SOCKET	IncomeSocket;
    static SOCKET	OutcomeSocket;
    static Address_Type	OutcomeAddress;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {10, 0};

	static struct timeval	TimeLimit = LongTime;

	#define LEFT_LENGTH_SL (sizeof(RequestBuffer) - sizeof(IHeader));
	static char		RequestBuffer[2048];
	static IHeader	*Header = (IHeader *)RequestBuffer;
	static char		RequestEntity = RequestBuffer + sizeof(IHeader);

	IncomeSocket = TryBindLocal(Ipv6_Aviliable(), 10200, NULL);
	OutcomeSocket = TryBindLocal(Ipv6_Aviliable(), 10300, &OutcomeAddress);

	if( IncomeSocket == INVALID_SOCKET || OutcomeSocket == INVALID_SOCKET )
	{
		return -416;
	}

    if( SocketPuller_Init(&Puller) != 0 )
    {
        return -423;
    }

    Puller.Add(&Puller, IncomeSocket, NULL, 0);
    Puller.Add(&Puller, OutcomeSocket, NULL, 0);

    if( HostsContext_Init(&Context) != 0 )
    {
        return -431;
    }

    srand(time(NULL));

	while( TRUE )
	{
	    SOCKET  Pulled;

	    Pulled = Puller.Select(&Puller, &TimeLimit, NULL, TRUE, FALSE);
	    switch( Pulled )
	    {
        case INVALID_SOCKET:
            Context.Swep(&Context);
            TimeLimit = LongTime
            break;

        case IncomeSocket:
            TimeLimit = ShortTime;
            /* Recursive query */
            {
                int State;

                State = recvfrom(IncomeSocket,
                                 RequestEntity,
                                 LEFT_LENGTH_SL,
								 0,
								 NULL,
								 NULL
								 );

                if( State < 1 )
                {
                    break;
                }

                /** TODO: Go on */
            }
            break;

        case OutcomeSocket:
            TimeLimit = ShortTime;
            /** TODO: Go on */
            break;
	    }

		ReadySet = ReadSet;

		switch( select(MaxFd + 1, &ReadySet, NULL, NULL, &TimeLimit) )
		{
			case SOCKET_ERROR:
				break;

			case 0:
				if( InternalInterface_QueryContextSwep(&Context, 10, NULL) == TRUE )
				{
					TimeLimit = LongTime;
				} else {
					TimeLimit = ShortTime;
				}
				break;

			default:
				TimeLimit = ShortTime;

				if( FD_ISSET(HostsIncomeSocket, &ReadySet) )
				{
				    /* Recursive query */
					int State;
					int TotalLength = 0;
					int	MatchState;
					const char *MatchResult = NULL;
					BOOL GotLock = FALSE;
					BOOL NeededSendBack = TRUE;

					State = recvfrom(HostsIncomeSocket,
									RequestEntity,
									sizeof(RequestEntity),
									0,
									NULL,
									NULL
									);

					if( State < 1 )
					{
						break;
					}

					MatchState = Hosts_Match(&MainStaticContainer, Header -> RequestingDomain, Header -> RequestingType, &MatchResult);
					if( MatchState == MATCH_STATE_NONE && MainDynamicContainer != NULL )
					{
						RWLock_WrLock(HostsLock);
						MatchState = Hosts_Match((HostsContainer *)MainDynamicContainer, Header -> RequestingDomain, Header -> RequestingType, &MatchResult);

						GotLock = TRUE;
					}

					switch( MatchState )
					{
						case MATCH_STATE_PERFECT:
							ERRORMSG("A Bug hit(471).\n");
							break;

						case MATCH_STATE_ONLY_CNAME:
							InternalInterface_QueryContextAddHosts(&Context,
																	Header,
																	NewIdentifier,
																	ELFHash(MatchResult, 0)
																	);

							GetAnswersByName(HostsOutcomeSocket, &(OutcomeAddress), NewIdentifier, MatchResult, Header -> RequestingType);
							++NewIdentifier;
							NeededSendBack = FALSE;
							break;

						default:
							NeededSendBack = FALSE;
							break;
					}

					if( GotLock == TRUE )
					{
						RWLock_UnWLock(HostsLock);
					}

					if( NeededSendBack == TRUE )
					{
						if( Header -> NeededHeader == TRUE )
						{
							sendto(SendBackSocket,
									(const char *)Header,
									TotalLength,
									0,
									(const struct sockaddr *)&(Header -> BackAddress.Addr),
									GetAddressLength(Header -> BackAddress.family)
									);
						} else {
							sendto(SendBackSocket,
									RequestEntity + sizeof(ControlHeader),
									TotalLength - sizeof(ControlHeader),
									0,
									(const struct sockaddr *)&(Header -> BackAddress.Addr),
									GetAddressLength(Header -> BackAddress.family)
									);
						}

						ShowNormalMessage(Header -> Agent,
											Header -> RequestingDomain,
											RequestEntity + sizeof(ControlHeader),
											TotalLength - sizeof(ControlHeader),
											'H'
											);
					}

				} else {
				    /* Response of recursive query */
					int		State;
					static char		NewlyGeneratedRocord[2048];
					ControlHeader	*NewHeader = (ControlHeader *)NewlyGeneratedRocord;

					DnsSimpleParser p;
					DnsSimpleParserIterator i;
					DnsGenerator g;

					char	*DNSResult = RequestEntity + sizeof(ControlHeader);

                    int32_t	EntryNumber;
					QueryContextEntry	*Entry;

					BOOL ToBreak = FALSE;

					int CompressedLength;

					State = recvfrom(HostsOutcomeSocket,
									RequestEntity,
									sizeof(RequestEntity),
									0,
									NULL,
									NULL
									);

					if( State < 1 )
					{
						break;
					}

					if( DnsSimpleParser_Init(&p,
                                             DNSResult,
                                             State - sizeof(ControlHeader),
                                             FALSE
                                             ) != 0
                        )
                    {
                        break;
                    }

                    if( DnsSimpleParserIterator_Init(&i, &p) != 0 )
                    {
                        break;
                    }

                    if( DnsGenerator_Init(&g,
                                          NewlyGeneratedRocord + sizeof(ControlHeader),
                                          sizeof(NewlyGeneratedRocord) - sizeof(ControlHeader),
                                          NULL, 0, FALSE
                                          ) != 0
                       )
                    {
                        break;
                    }

                    g.CopyHeader(&g, DNSResult, FALSE);

					EntryNumber = InternalInterface_QueryContextFind(&Context,
																	*(uint16_t *)DNSResult,
																	Header -> RequestingDomainHashValue
																	);

					if( EntryNumber < 0 )
					{
						break;
					}

					Entry = Bst_GetDataByNumber(&Context, EntryNumber);

					g.CopyIdentifier(&g, Entry->Context.Hosts.Identifier);

                    if( g.Question(&g, Entry->Domain, Entry->Type, DNS_CLASS_IN)
                        != 0
                        )
                    {
                        break;
                    }

                    if( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER )
                    {
                        break;
                    }

                    if( g.CName(&g, Entry->Domain, Header->RequestingDomain, 60)
                        != 0
                        )
                    {
                        break;
                    }

                    i.GotoAnswers(&i);
                    ToBreak = FALSE;
                    while( i.Next(&i) != NULL &&
                           i.Purpose == DNS_RECORD_PURPOSE_ANSWER &&
                           !ToBreak
                           )
                    {
                        switch( i.Type )
                        {
                        case DNS_TYPE_CNAME:
                            if( g.CopyCName(&g, &i) != 0 )
                            {
                                ToBreak = TRUE;
                            }
                            break;

                        case DNS_TYPE_A:
                            if( g.CopyA(&g, &i) != 0 )
                            {
                                ToBreak = TRUE;
                            }
                            break;

                        case DNS_TYPE_AAAA:
                            if( g.CopyAAAA(&g, &i) != 0 )
                            {
                                ToBreak = TRUE;
                            }
                            break;

                        default:
                            ToBreak = TRUE;
                            break;
                        }
                    }

                    if( ToBreak )
                    {
                        break;
                    }

					if( Entry->EDNSEnabled == TRUE )
					{
					    while( g.NextPurpose(&g) !=
                               DNS_RECORD_PURPOSE_ADDITIONAL
                               );

                        if( g.EDns(&g, 1280) != 0 )
                        {
                            break;
                        }
					}

					/* Now we can compress it */
					CompressedLength = DNSCompress(g.Buffer, g.Length(&g));

					if( CompressedLength < 0 )
                    {
                        break;
                    }

					/* Send*/
					if( Entry->NeededHeader == TRUE )
					{
						strncpy(NewHeader->RequestingDomain,
                                Entry->Domain,
                                sizeof(NewHeader->RequestingDomain)
                                );
                        (NewHeader->RequestingDomain)[sizeof(NewHeader->RequestingDomain) - 1] = '\0';
						NewHeader->RequestingDomainHashValue = Entry->Context.Hosts.HashValue;

						sendto(SendBackSocket,
								NewlyGeneratedRocord,
								CompressedLength + sizeof(ControlHeader),
								0,
								(const struct sockaddr *)&(Entry->Context.Hosts.BackAddress.Addr),
								GetAddressLength(Entry->Context.Hosts.BackAddress.family)
								);
					} else {
						sendto(SendBackSocket,
								NewlyGeneratedRocord + sizeof(ControlHeader),
								CompressedLength,
								0,
								(const struct sockaddr *)&(Entry -> Context.Hosts.BackAddress.Addr),
								GetAddressLength(Entry -> Context.Hosts.BackAddress.family)
								);
					}

					InternalInterface_QueryContextRemoveByNumber(&Context, EntryNumber);

					ShowNormalMessage(Entry -> Agent,
										Entry -> Domain,
										NewlyGeneratedRocord + sizeof(ControlHeader),
										CompressedLength,
										'H'
										);
				}
		}
	}
}
