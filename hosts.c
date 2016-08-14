#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "hosts.h"
#include "dnsrelated.h"
#include "dnsgenerator.h"
#include "common.h"
#include "utils.h"
#include "downloader.h"
#include "readline.h"
#include "internalsocket.h"
#include "goodiplist.h"
#include "rwlock.h"

static BOOL			StaticHostsInited = FALSE;

static int			UpdateInterval;
static int			HostsRetryInterval;

static BOOL			DisableIpv6WhenIpv4Exists = FALSE;

static const char 	*File = NULL;

static ThreadHandle	GetHosts_Thread;
static RWLock		HostsLock;

static volatile HostsContainer	*MainDynamicContainer = NULL;

static void DynamicHosts_FreeHostsContainer(HostsContainer *Container)
{
	StringChunk_Free(&(Container -> Ipv4Hosts), FALSE);
	StringChunk_Free(&(Container -> Ipv6Hosts), FALSE);
	StringChunk_Free(&(Container -> CNameHosts), FALSE);
	StringChunk_Free(&(Container -> ExcludedDomains), FALSE);
    Container->Domains.Free(&(Container -> Domains));
	Container->IPs.Free(&(Container->IPs));
}

static int DynamicHosts_Load(void)
{
	FILE			*fp;
	char			Buffer[320];
	ReadLineStatus	Status;

	int		IPv4Count = 0, IPv6Count = 0, CNameCount = 0, ExcludedCount = 0;

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

	if( Hosts_InitContainer(TempContainer) != 0 )
	{
		fclose(fp);

		SafeFree(TempContainer);
		return -1;
	}

	while( TRUE )
	{
		Status = ReadLine(fp, Buffer, sizeof(Buffer));
		if( Status == READ_FAILED_OR_END )
			break;

		switch( Hosts_LoadFromMetaLine(TempContainer, Buffer) )
		{
			case HOSTS_TYPE_AAAA:
				++IPv6Count;
				break;

			case HOSTS_TYPE_A:
				++IPv4Count;
				break;

			case HOSTS_TYPE_CNAME:
				++CNameCount;
				break;

			case HOSTS_TYPE_EXCLUEDE:
				++ExcludedCount;
				break;

			case HOSTS_TYPE_CNAME_EXCLUEDE:
				++CNameCount;
				++ExcludedCount;
				break;

			default:
				break;
		}

		if( Status == READ_TRUNCATED )
		{
			ERRORMSG("Hosts is too long : %s\n", Buffer);
			ReadLine_GoToNextLine(fp);
		}
	}

	RWLock_WrLock(HostsLock);
	if( MainDynamicContainer != NULL )
	{
		DynamicHosts_FreeHostsContainer((HostsContainer *)MainDynamicContainer);
		SafeFree((void *)MainDynamicContainer);
	}
	MainDynamicContainer = TempContainer;

	RWLock_UnWLock(HostsLock);

	INFO("Loading hosts file completed, %d IPv4 Hosts, %d IPv6 Hosts, %d CName Redirections, %d items are excluded.\n",
		IPv4Count,
		IPv6Count,
		CNameCount,
		ExcludedCount);

	fclose(fp);
	return 0;
}

static void GetHostsFromInternet_Failed(int ErrorCode, const char *URL, const char *File)
{
	ERRORMSG("Getting Hosts %s failed. Waiting %d second(s) to try again.\n", URL, HostsRetryInterval);
}

static void GetHostsFromInternet_Succeed(const char *URL, const char *File)
{
	INFO("Hosts %s saved.\n", URL);
}

static void GetHostsFromInternet_Thread(ConfigFileInfo *ConfigInfo)
{
	const char	*Script = ConfigGetRawString(ConfigInfo, "HostsScript");
	int			DownloadState;
	const char	**URLs;

	StringList  *Hosts = ConfigGetStringList(ConfigInfo, "Hosts");

	URLs = Hosts->ToCharPtrArray(Hosts);

	while(1)
	{
		if( URLs[1] == NULL )
		{
			INFO("Getting hosts from %s ...\n", URLs[0]);
		} else {
			INFO("Getting hosts from various places ...\n");
		}

		DownloadState = GetFromInternet_MultiFiles(URLs, File, HostsRetryInterval, -1, GetHostsFromInternet_Failed, GetHostsFromInternet_Succeed);
		if( DownloadState == 0 )
		{
			INFO("Hosts saved at %s.\n", File);

			if( Script != NULL )
			{
				INFO("Running script ...\n");
				system(Script);
			}

			DynamicHosts_Load();

			if( UpdateInterval < 0 )
			{
				break;
			}
		} else {
			ERRORMSG("Getting hosts file(s) failed.\n");
		}

		SLEEP(UpdateInterval * 1000);
	}

	SafeFree(URLs);
}

static const char *Hosts_FindFromContainer(HostsContainer *Container, StringChunk *SubContainer, const char *Name)
{
	HostsPosition *IP;

	if( StringChunk_Match(SubContainer, Name, NULL, (char **)&IP) == TRUE )
	{
		return IP->Position;
	} else {
		return NULL;
	}
}

static const char *Hosts_FindIPv4(HostsContainer *Container, const char *Name)
{
	return Hosts_FindFromContainer(Container, &(Container -> Ipv4Hosts), Name);
}

static const char *Hosts_FindIPv6(HostsContainer *Container, const char *Name)
{
	return Hosts_FindFromContainer(Container, &(Container -> Ipv6Hosts), Name);
}

static const char *Hosts_FindCName(HostsContainer *Container, const char *Name)
{
	return Hosts_FindFromContainer(Container, &(Container -> CNameHosts), Name);
}

static const char *Hosts_FindGoodIPList(HostsContainer *Container, const char *Name)
{
	const char *Result = Hosts_FindFromContainer(Container, &(Container -> GoodIpLists), Name);

	if( Result == NULL )
	{
		return NULL;
	}

	return GoodIpList_Get(Result);
}

static BOOL Hosts_IsExcludedDomain(HostsContainer *Container, const char *Name)
{
	return StringChunk_Match((StringChunk *)&(Container -> ExcludedDomains), Name, NULL, NULL);
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

static int Hosts_GenerateSingleRecord(DNSRecordType Type, const char *IPOrCName, char *Buffer)
{
	int RecordLength;
	int DataLength;

	switch( Type )
	{
		case DNS_TYPE_A:
			DataLength = 4;
			RecordLength = 2 + 2 + 2 + 4 + 2 + DataLength;
			break;

		case DNS_TYPE_AAAA:
			DataLength = 16;
			RecordLength = 2 + 2 + 2 + 4 + 2 + DataLength;
			break;

		case DNS_TYPE_CNAME:
			DataLength = strlen(IPOrCName) + 2;
			RecordLength = 2 + 2 + 2 + 4 + 2 + DataLength;
			break;

		default:
			return -1;
			break;
	}

	DNSGenResourceRecord(Buffer + 1, INT_MAX, "", Type, DNS_CLASS_IN, 60, IPOrCName, DataLength, FALSE);

	Buffer[0] = 0xC0;
	Buffer[1] = 0x0C;

	return RecordLength;
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

	int RequestLength = sizeof(ControlHeader) + 12;

	char *NamePos = DNSEntity + 0x0C;

	RequestLength += DNSGenQuestionRecord(NamePos, sizeof(RequestEntity.Entity) - 12, Name, Type, DNS_CLASS_IN);
	if( RequestLength == sizeof(ControlHeader) + 12 )
	{
        return -1;
	}

	RequestEntity.Header.NeededHeader = TRUE;
	strcpy(RequestEntity.Header.Agent, "CNameRedirect");
	memcpy(&(RequestEntity.Header.BackAddress), BackAddress, sizeof(Address_Type));
	strcpy(RequestEntity.Header.RequestingDomain, Name);
	RequestEntity.Header.RequestingType = Type;
	RequestEntity.Header.RequestingDomainHashValue = ELFHash(Name, 0);
	*(uint16_t *)DNSEntity = Identifier;

	return InternalInterface_SendTo(INTERNAL_INTERFACE_UDP_LOOPBACK_LOCAL, Socket, (char *)&RequestEntity, RequestLength);
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
							ERRORMSG("A Bug hit.\n");
							{
								BOOL EDNSEnabled = FALSE;

								if( DNSRemoveEDNSPseudoRecord(RequestEntity + sizeof(ControlHeader), &State) == EDNS_REMOVED )
								{
									EDNSEnabled = TRUE;
								}

								((DNSHeader *)(RequestEntity + sizeof(ControlHeader))) -> Flags.Direction = 1;
								((DNSHeader *)(RequestEntity + sizeof(ControlHeader))) -> Flags.AuthoritativeAnswer = 0;
								((DNSHeader *)(RequestEntity + sizeof(ControlHeader))) -> Flags.RecursionAvailable = 1;
								((DNSHeader *)(RequestEntity + sizeof(ControlHeader))) -> Flags.ResponseCode = 0;
								((DNSHeader *)(RequestEntity + sizeof(ControlHeader))) -> Flags.Type = 0;
								DNSSetAnswerCount(RequestEntity + sizeof(ControlHeader), 1);
								TotalLength = State;
								TotalLength += Hosts_GenerateSingleRecord(Header -> RequestingType, MatchResult, RequestEntity + State);
								NeededSendBack = TRUE;

								if( EDNSEnabled == TRUE )
								{
									int	NewEntityLength = 0;

									NewEntityLength = TotalLength - sizeof(ControlHeader);
									DNSAppendEDNSPseudoRecord(RequestEntity + sizeof(ControlHeader), &NewEntityLength);
									TotalLength = NewEntityLength + sizeof(ControlHeader);
								}
							}
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

						ShowNormalMassage(Header -> Agent,
											Header -> RequestingDomain,
											RequestEntity + sizeof(ControlHeader),
											TotalLength - sizeof(ControlHeader),
											'H'
											);
					}

				} else {
					int		State;
					static char		NewlyGeneratedRocord[2048];
					ControlHeader	*NewHeader = (ControlHeader *)NewlyGeneratedRocord;

					int 	TrimedLength;
					int		RestLength;

					int NewGeneratedLength = sizeof(ControlHeader);
					int CompressedLength;

					int32_t	EntryNumber;
					QueryContextEntry	*Entry;

					char	*DNSResult = RequestEntity + sizeof(ControlHeader);

					char	*AnswersPos;

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

					DNSSetNameServerCount(DNSResult, 0);

					TrimedLength = DNSJumpOverAnswerRecords(DNSResult) - DNSResult;

					AnswersPos = DNSJumpOverQuestionRecords(DNSResult);

					if( DNSExpandCName_MoreSpaceNeeded(DNSResult, TrimedLength) > sizeof(RequestEntity) - State )
					{
						break;
					}

					DNSExpandCName(DNSResult, TrimedLength);

					EntryNumber = InternalInterface_QueryContextFind(&Context,
																	*(uint16_t *)DNSResult,
																	Header -> RequestingDomainHashValue
																	);

					if( EntryNumber < 0 )
					{
						break;
					}

					Entry = Bst_GetDataByNumber(&Context, EntryNumber);

					memcpy(NewlyGeneratedRocord + NewGeneratedLength, DNSResult, 12);
					*(uint16_t *)(NewlyGeneratedRocord + sizeof(ControlHeader)) = Entry -> Context.Hosts.Identifier;
					NewGeneratedLength += 12;

					State = DNSGenQuestionRecord(NewlyGeneratedRocord + NewGeneratedLength,
												 sizeof(NewlyGeneratedRocord) - NewGeneratedLength,
												 Entry -> Domain,
												 Entry -> Type,
												 DNS_CLASS_IN
												 );
					if( State > 0 )
					{
						NewGeneratedLength += State;
					} else {
						break;
					}

					State = DNSGenResourceRecord(NewlyGeneratedRocord + NewGeneratedLength,
												 sizeof(NewlyGeneratedRocord) - NewGeneratedLength,
												 Entry -> Domain,
												 DNS_TYPE_CNAME,
												 DNS_CLASS_IN,
												 60,
												 DNSJumpHeader(DNSResult),
												 strlen(DNSJumpHeader(DNSResult)) + 1,
												 FALSE
												 );
					if( State > 0 )
					{
						NewGeneratedLength += State;
					} else {
						break;
					}

					RestLength = DNSJumpOverAnswerRecords(DNSResult) - AnswersPos;
					if( RestLength >= 0 && sizeof(NewlyGeneratedRocord) - NewGeneratedLength > (unsigned int)RestLength )
					{
						memcpy(NewlyGeneratedRocord + NewGeneratedLength, AnswersPos, RestLength);
						NewGeneratedLength += RestLength;
					} else {
						break;
					}

					DNSSetNameServerCount(NewlyGeneratedRocord + sizeof(ControlHeader), 0);
					DNSSetAnswerCount(NewlyGeneratedRocord + sizeof(ControlHeader), DNSGetAnswerCount(NewlyGeneratedRocord + sizeof(ControlHeader)) + 1);

					CompressedLength = DNSCompress(NewlyGeneratedRocord + sizeof(ControlHeader), NewGeneratedLength - sizeof(ControlHeader));

					if( Entry -> EDNSEnabled == TRUE )
					{
						memcpy(NewlyGeneratedRocord + CompressedLength + sizeof(ControlHeader), OptPseudoRecord, OPT_PSEUDORECORD_LENGTH);
						CompressedLength += OPT_PSEUDORECORD_LENGTH;
						DNSSetAdditionalCount(NewlyGeneratedRocord + sizeof(ControlHeader), 1);
					} else {
						DNSSetAdditionalCount(NewlyGeneratedRocord + sizeof(ControlHeader), 0);
					}

					if( Entry -> NeededHeader == TRUE )
					{
						strcpy(NewHeader -> RequestingDomain, Entry -> Domain);
						NewHeader -> RequestingDomainHashValue = Entry -> Context.Hosts.HashValue;

						sendto(SendBackSocket,
								NewlyGeneratedRocord,
								CompressedLength + sizeof(ControlHeader),
								0,
								(const struct sockaddr *)&(Entry -> Context.Hosts.BackAddress.Addr),
								GetAddressLength(Entry -> Context.Hosts.BackAddress.family)
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

					ShowNormalMassage(Entry -> Agent,
										Entry -> Domain,
										NewlyGeneratedRocord + sizeof(ControlHeader),
										CompressedLength,
										'H'
										);
				}
		}
	}

}

int Hosts_Try(char *Content, int *ContentLength)
{
	ControlHeader	*Header = (ControlHeader *)Content;
	char			*RequestEntity = Content + sizeof(ControlHeader);

	int			MatchState;
	const char	*MatchResult;
	BOOL		GotLock = FALSE;

	MatchState = Hosts_Match(&MainStaticContainer, Header -> RequestingDomain, Header -> RequestingType, &MatchResult);
	if( MatchState == MATCH_STATE_NONE && MainDynamicContainer != NULL )
	{
		RWLock_WrLock(HostsLock);
		MatchState = Hosts_Match((HostsContainer *)MainDynamicContainer, Header -> RequestingDomain, Header -> RequestingType, &MatchResult);
		GotLock = TRUE;
	}

	if( MatchState == MATCH_STATE_PERFECT )
	{
		BOOL EDNSEnabled = FALSE;

		switch( DNSRemoveEDNSPseudoRecord(RequestEntity, ContentLength) )
		{
			case EDNS_REMOVED:
				EDNSEnabled = TRUE;
				break;

			case EDNS_NO_AR:
				EDNSEnabled = FALSE;
				break;

			default:
				if( GotLock == TRUE )
				{
					RWLock_UnWLock(HostsLock);
				}

				return MATCH_STATE_NONE;
		}

		((DNSHeader *)(RequestEntity)) -> Flags.Direction = 1;
		((DNSHeader *)(RequestEntity)) -> Flags.AuthoritativeAnswer = 0;
		((DNSHeader *)(RequestEntity)) -> Flags.RecursionAvailable = 1;
		((DNSHeader *)(RequestEntity)) -> Flags.ResponseCode = 0;
		((DNSHeader *)(RequestEntity)) -> Flags.Type = 0;
		DNSSetAnswerCount(RequestEntity, 1);
		*ContentLength += Hosts_GenerateSingleRecord(Header -> RequestingType, MatchResult, Content + *ContentLength);

		if( EDNSEnabled == TRUE )
		{
			int	NewEntityLength = 0;

			NewEntityLength = *ContentLength - sizeof(ControlHeader);
			DNSAppendEDNSPseudoRecord(RequestEntity, &NewEntityLength);
			*ContentLength = NewEntityLength + sizeof(ControlHeader);
		}
	}

	if( GotLock == TRUE )
	{
		RWLock_UnWLock(HostsLock);
	}

	return MatchState;
}

int DynamicHosts_Init(ConfigFileInfo *ConfigInfo)
{
	const char	*Path;

	StaticHostsInited = ( StaticHosts_Init(ConfigInfo) >= 0 );

	DisableIpv6WhenIpv4Exists = ConfigGetBoolean(ConfigInfo, "DisableIpv6WhenIpv4Exists");
	Path = ConfigGetRawString(ConfigInfo, "Hosts");

	if( Path == NULL )
	{
		File = NULL;
		return 0;
	}

	UpdateInterval = ConfigGetInt32(ConfigInfo, "HostsUpdateInterval");
	HostsRetryInterval = ConfigGetInt32(ConfigInfo, "HostsRetryInterval");

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

	return 0;

}

int DynamicHosts_Start(ConfigFileInfo *ConfigInfo)
{
	if( StaticHostsInited == TRUE || File != NULL )
	{
		ThreadHandle	t;

		CREATE_THREAD(DynamicHosts_SocketLoop, NULL, t);
		DETACH_THREAD(t);

		if( File != NULL )
		{
			CREATE_THREAD(GetHostsFromInternet_Thread, ConfigInfo, GetHosts_Thread);
		}
	}

	return 0;
}
