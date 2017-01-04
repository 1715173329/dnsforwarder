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
#include "rwlock.h"

static BOOL			StaticHostsInited = FALSE;
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

	StaticHostsInited = ( StaticHosts_Init(ConfigInfo) >= 0 );

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

static int Hosts_Match(HostsContainer *Container, const char *Name, DNSRecordType Type, const char **Result)
{
	if( Container == NULL )
	{
		return MATCH_STATE_NONE;
	}

	if( Hosts_IsExcludedDomain(Container, Name) == TRUE )
	{
		return MATCH_STATE_DISABLED;
	}

	switch( Type )
	{
		case DNS_TYPE_A:
			*Result = Hosts_FindIPv4(Container, Name);
			if( *Result == NULL )
			{
				*Result = Hosts_FindGoodIPList(Container, Name);
				if( *Result == NULL )
				{
					break;
				}
			}

			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_AAAA:
			if( DisableIpv6WhenIpv4Exists == TRUE && (Hosts_FindIPv4(Container, Name) != NULL || Hosts_FindGoodIPList(Container, Name) != NULL) )
			{
				return MATCH_STATE_DISABLE_IPV6;
			}

			*Result = Hosts_FindIPv6(Container, Name);
			if( *Result == NULL )
			{
				break;
			}

			return MATCH_STATE_PERFECT;
			break;

		case DNS_TYPE_CNAME:
			*Result = Hosts_FindCName(Container, Name);
			if( *Result == NULL )
			{
				return MATCH_STATE_NONE;
			}

			return MATCH_STATE_PERFECT;
			break;

		default:
			return MATCH_STATE_NONE;
			break;
	}

	*Result = Hosts_FindCName(Container, Name);
	if( *Result == NULL )
	{
		return MATCH_STATE_NONE;
	}

	return MATCH_STATE_ONLY_CNAME;
}

static int GetAnswersByName(SOCKET Socket, Address_Type *BackAddress, int Identifier, const char *Name, DNSRecordType Type)
{
	static struct _RequestEntity {
		ControlHeader	Header;
		char			Entity[384];
	} RequestEntity = {
		{CONTROLHEADER__PAD},
		{
			00, 00, /* QueryIdentifier */
			01, 00, /* Flags */
			00, 01, /* QuestionCount */
			00, 00, /* AnswerCount */
			00, 00, /* NameServerCount */
			00, 00, /* AdditionalCount */
			/* DNS Header end */
		}
	};

	static char *DNSEntity = RequestEntity.Entity;

	DnsGenerator g;

	*(uint16_t *)DNSEntity = Identifier;
	DNSEntity[4] = 0;
	DNSEntity[5] = 0;

	if( DnsGenerator_Init(&g,
                          DNSEntity,
                          sizeof(RequestEntity.Entity),
                          DNSEntity,
                          DNS_HEADER_LENGTH,
                          FALSE
                       ) != 0
      )
    {
        return -1;
    }

    if( g.Question(&g, Name, Type, DNS_CLASS_IN) != 0 )
    {
        return -2;
    }

	RequestEntity.Header.NeededHeader = TRUE;
	strncpy(RequestEntity.Header.Agent,
            "CNameRedirect",
            sizeof(RequestEntity.Header.Agent)
            );
    RequestEntity.Header.Agent[sizeof(RequestEntity.Header.Agent) -1 ] = '\0';
	memcpy(&(RequestEntity.Header.BackAddress), BackAddress, sizeof(Address_Type));
	strncpy(RequestEntity.Header.RequestingDomain,
            Name,
            sizeof(RequestEntity.Header.RequestingDomain)
            );
    RequestEntity.Header.RequestingDomain[sizeof(RequestEntity.Header.RequestingDomain) - 1] = '\0';
	RequestEntity.Header.RequestingType = Type;
	RequestEntity.Header.RequestingDomainHashValue = ELFHash(Name, 0);

    return InternalInterface_SendTo(INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL,
                                    Socket,
                                    (char *)&RequestEntity,
                                    g.Length(&g) + sizeof(ControlHeader)
                                    );

}

int DynamicHosts_SocketLoop(void)
{
	static uint16_t	NewIdentifier;

	static QueryContext	Context;

    SOCKET	HostsIncomeSocket;
    SOCKET	HostsOutcomeSocket;
    Address_Type	OutcomeAddress;
    SOCKET	SendBackSocket;

	static fd_set	ReadSet, ReadySet;

	static const struct timeval	LongTime = {3600, 0};
	static const struct timeval	ShortTime = {10, 0};

	struct timeval	TimeLimit = LongTime;

	int		MaxFd;

	static char		RequestEntity[2048];
	ControlHeader	*Header = (ControlHeader *)RequestEntity;

    HostsIncomeSocket = InternalInterface_TryOpenLocal(10200, INTERNAL_INTERFACE_HOSTS);
    HostsOutcomeSocket = InternalInterface_TryBindAddress(MAIN_WORKING_ADDRESS, 10225, &(OutcomeAddress));

	if( HostsOutcomeSocket == INVALID_SOCKET )
	{
		return -1;
	}

	SendBackSocket = InternalInterface_GetSocket(INTERNAL_INTERFACE_UDP_INCOME);

	MaxFd = HostsIncomeSocket > HostsOutcomeSocket ? HostsIncomeSocket : HostsOutcomeSocket;
	FD_ZERO(&ReadSet);
	FD_ZERO(&ReadySet);
	FD_SET(HostsIncomeSocket, &ReadSet);
	FD_SET(HostsOutcomeSocket, &ReadSet);

	InternalInterface_InitQueryContext(&Context);

	NewIdentifier = rand();

	while( TRUE )
	{
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

int Hosts_Try(char *Content, int *ContentLength, int BufferLength)
{
	ControlHeader	*Header = (ControlHeader *)Content;
	char			*RequestEntity = Content + sizeof(ControlHeader);

	int			MatchState;
	const char	*MatchResult;
	BOOL		GotLock = FALSE;

	/** TODO: You should also check the queried class */
    if( Header->RequestingType != DNS_TYPE_CNAME &&
        Header->RequestingType != DNS_TYPE_A &&
        Header->RequestingType != DNS_TYPE_AAAA
        )
    {
        return MATCH_STATE_NONE;
    }

	/* Matching stage */
	MatchState = Hosts_Match(&MainStaticContainer,
                             Header -> RequestingDomain,
                             Header -> RequestingType,
                             &MatchResult
                             );
	if( MatchState == MATCH_STATE_NONE && MainDynamicContainer != NULL )
	{
		RWLock_WrLock(HostsLock);
		MatchState = Hosts_Match((HostsContainer *)MainDynamicContainer,
                                 Header -> RequestingDomain,
                                 Header -> RequestingType,
                                 &MatchResult
                                 );
		GotLock = TRUE;
	}
    /* Matching done */

	if( MatchState == MATCH_STATE_PERFECT )
	{
	    DnsSimpleParser p;

	    BOOL HasEdns;

        DnsGenerator g;

        char *HereToGenerate = Content + *ContentLength;
        int LeftBufferLength = BufferLength - *ContentLength;

        int ResultLength;

	    if( DnsSimpleParser_Init(&p,
                                 RequestEntity,
                                 *ContentLength - sizeof(ControlHeader),
                                 FALSE
                                 )
            != 0 )
        {
            if( GotLock == TRUE )
            {
                RWLock_UnWLock(HostsLock);
            }

            return MATCH_STATE_NONE;
        }

        HasEdns = p.HasType(&p,
                            DNS_RECORD_PURPOSE_ADDITIONAL,
                            DNS_CLASS_UNKNOWN,
                            DNS_TYPE_OPT
                            );

        if( DnsGenerator_Init(&g,
                              HereToGenerate,
                              LeftBufferLength,
                              RequestEntity,
                              *ContentLength - sizeof(ControlHeader),
                              TRUE
                              )
           != 0)
        {
            if( GotLock == TRUE )
            {
                RWLock_UnWLock(HostsLock);
            }
            return MATCH_STATE_NONE;
        }

        g.Header->Flags.Direction = 1;
        g.Header->Flags.AuthoritativeAnswer = 0;
        g.Header->Flags.RecursionAvailable = 1;
        g.Header->Flags.ResponseCode = 0;
        g.Header->Flags.Type = 0;

        if( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ANSWER )
        {
            if( GotLock == TRUE )
            {
                RWLock_UnWLock(HostsLock);
            }
            return MATCH_STATE_NONE;
        }

        switch( Header->RequestingType )
        {
        case DNS_TYPE_CNAME:
            if( g.CName(&g, "a", MatchResult, 60) != 0 )
            {
                if( GotLock == TRUE )
                {
                    RWLock_UnWLock(HostsLock);
                }

                return MATCH_STATE_NONE;
            }
            break;

        case DNS_TYPE_A:
            if( g.RawData(&g,
                          "a",
                          Header->RequestingType,
                          DNS_CLASS_IN,
                          MatchResult,
                          4,
                          60
                          )
                != 0 )
            {
                if( GotLock == TRUE )
                {
                    RWLock_UnWLock(HostsLock);
                }
                return MATCH_STATE_NONE;
            }
            break;

        case DNS_TYPE_AAAA:
            if( g.RawData(&g,
                          "a",
                          Header->RequestingType,
                          DNS_CLASS_IN,
                          MatchResult,
                          16,
                          60
                          )
                != 0 )
            {
                if( GotLock == TRUE )
                {
                    RWLock_UnWLock(HostsLock);
                }
                return MATCH_STATE_NONE;
            }
            break;

        default:
            if( GotLock == TRUE )
            {
                RWLock_UnWLock(HostsLock);
            }
            return MATCH_STATE_NONE;
            break;
        }

        if( HasEdns )
        {
            while( g.NextPurpose(&g) != DNS_RECORD_PURPOSE_ADDITIONAL );
            if( g.EDns(&g, 1280) != 0 )
            {
                if( GotLock == TRUE )
                {
                    RWLock_UnWLock(HostsLock);
                }
                return MATCH_STATE_NONE;
            }
        }

        /* g will no longer be needed, and can be crapped */
        ResultLength = DNSCompress(HereToGenerate, g.Length(&g));
        if( ResultLength < 0 )
        {
            if( GotLock == TRUE )
            {
                RWLock_UnWLock(HostsLock);
            }
            return MATCH_STATE_NONE;
        }

        memmove(RequestEntity, HereToGenerate, ResultLength);
        *ContentLength = ResultLength + sizeof(ControlHeader);
	}

	if( GotLock == TRUE )
	{
		RWLock_UnWLock(HostsLock);
	}

	return MatchState;
}
