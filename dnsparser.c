#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <limits.h>
#include "dnsparser.h"
#include "dnsgenerator.h"
#include "utils.h"

const ElementDescriptor DNS_RECORD_A[] = {
	{DNS_IPV4_ADDR, "IPv4 Address"}
};

const ElementDescriptor DNS_RECORD_AAAA[] = {
	{DNS_IPV6_ADDR, "IPv6 Address"}
};

const ElementDescriptor DNS_RECORD_CNAME[] = {
	{DNS_LABELED_NAME,	"Canonical Name"}
};

const ElementDescriptor DNS_RECORD_SOA[] = {
	{DNS_LABELED_NAME,	"primary name server"},
	{DNS_LABELED_NAME,	"responsible mail addr"},
	{DNS_32BIT_UINT,	"serial"},
	{DNS_32BIT_UINT,	"refresh"},
	{DNS_32BIT_UINT,	"retry"},
	{DNS_32BIT_UINT,	"expire"},
	{DNS_32BIT_UINT,	"default TTL"},
};

const ElementDescriptor DNS_RECORD_DOMAIN_POINTER[] = {
	{DNS_LABELED_NAME,	"name"}
};

const ElementDescriptor DNS_RECORD_NAME_SERVER[] = {
	{DNS_LABELED_NAME,	"Name Server"}
};

const ElementDescriptor DNS_RECORD_MX[] = {
	{DNS_16BIT_UINT,	"Preference"},
	{DNS_LABELED_NAME,	"Mail Exchanger"}
};

const ElementDescriptor DNS_RECORD_TXT[] = {
	{DNS_CHARACTER_STRING,	"TXT"}
};

const ElementDescriptor DNS_RECORD_DNSKEY[] = {
	{DNS_DNSKEY_FLAGS,		"Flags"},
	{DNS_DNSKEY_PROTOCOL,	"Protocol"},
	{DNS_DNSKEY_ALGORITHM,	"Algorithm"},
	{DNS_DNSKEY_PUBLIC_KEY,	"Public Key"}
};

const ElementDescriptor DNS_RECORD_RRSIG[] = {
	{DNS_16BIT_UINT,		"Type Covered"},
	{DNS_DNSKEY_ALGORITHM,	"Algorithm"},
	{DNS_8BIT_UINT,			"Labels"},
	{DNS_32BIT_UINT,		"Original TTL"},
	{DNS_32BIT_UINT,		"Signature Expiration"},
	{DNS_32BIT_UINT,		"Signature Inception"},
	{DNS_16BIT_UINT,		"Key Tag"},
	{DNS_LABELED_NAME,		"Signer's Name"},
	{DNS_DNSSIG_SIGNATURE,	"Signature"}
};

static const struct _Type_Descriptor_DCount
{
	DNSRecordType			Type;
	const ElementDescriptor	*Descriptor;
	int						DCount;
	BOOL					Cached;
}Type_Descriptor_DCount[] = {
	{DNS_TYPE_A,		DNS_RECORD_A,		NUM_OF_DNS_RECORD_A,		TRUE},
	{DNS_TYPE_CNAME,	DNS_RECORD_CNAME,	NUM_OF_DNS_RECORD_CNAME,	TRUE},
	{DNS_TYPE_AAAA,		DNS_RECORD_AAAA,	NUM_OF_DNS_RECORD_AAAA,		TRUE},
	{DNS_TYPE_SOA,		DNS_RECORD_SOA,		NUM_OF_DNS_RECORD_SOA,		TRUE},
	{DNS_TYPE_PTR,		DNS_RECORD_DOMAIN_POINTER,	NUM_OF_DNS_RECORD_DOMAIN_POINTER, TRUE},
	{DNS_TYPE_NS,		DNS_RECORD_NAME_SERVER,	NUM_OF_DNS_RECORD_NAME_SERVER, TRUE},
	{DNS_TYPE_MX,		DNS_RECORD_MX,		NUM_OF_DNS_RECORD_MX,		TRUE},
	{DNS_TYPE_TXT,		DNS_RECORD_TXT,		NUM_OF_DNS_RECORD_TXT,		FALSE},
	{DNS_TYPE_DNSKEY,	DNS_RECORD_DNSKEY,	NUM_OF_DNS_RECORD_DNSKEY,	TRUE},
	{DNS_TYPE_RRSIG,	DNS_RECORD_RRSIG,	NUM_OF_DNS_RECORD_RRSIG,	FALSE}

};

int DNSGetDescriptor(DNSRecordType Type, BOOL NeededCache, const ElementDescriptor **Buffer)
{
	int loop;

	for(loop = 0; loop != sizeof(Type_Descriptor_DCount) / sizeof(struct _Type_Descriptor_DCount); ++loop)
	{
		if( Type_Descriptor_DCount[loop].Type == Type )
		{
			if( NeededCache == TRUE && Type_Descriptor_DCount[loop].Cached == FALSE )
			{
				*Buffer = NULL;
				return 0;
			} else {
				*Buffer = Type_Descriptor_DCount[loop].Descriptor;
				return Type_Descriptor_DCount[loop].DCount;
			}
		}
	}

	*Buffer = NULL;
	return 0;
}

BOOL DNSIsLabeledName(char *DNSBody, char *Start)
{
	return FALSE;
}

const char *DNSJumpOverName(const char *NameStart)
{
	return NameStart + DNSGetHostName(NULL, INT_MAX, NameStart, NULL, 0);
}

const char *DNSGetQuestionRecordPosition(const char *DNSBody, int Num)
{
	const char *QR = DNSJumpHeader(DNSBody);
	int QuestionCount = DNSGetQuestionCount(DNSBody);

	if( Num < 1 )
	{
		return NULL;
	}

	if( Num > QuestionCount )
	{
		Num = QuestionCount + 1;
	}

	for(; Num != 1; --Num)
		QR = DNSJumpOverName(QR) + 4;

	return QR;
}

const char *DNSGetAnswerRecordPosition(const char *DNSBody, int Num)
{
	const char *SR = DNSJumpOverQuestionRecords(DNSBody);
	int AnswerCount = DNSGetAnswerCount(DNSBody);

	if( Num < 1 )
	{
		return NULL;
	}

	if( Num > AnswerCount )
	{
		Num = AnswerCount + 1;
	}

	for(; Num != 1; --Num)
		SR = DNSJumpOverName(SR) + 10 + DNSGetResourceDataLength(SR);

	return SR;
}

/* Labels length returned */
int DNSGetHostName(const char *DNSBody, int DNSBodyLength, const char *NameStart, char *buffer, int BufferLength)
{
	char *BufferItr = buffer;
	const char *NameItr = NameStart;
	int LabelsLength = 0;
	BOOL Redirected = FALSE;
	int LabelCount = GET_8_BIT_U_INT(NameItr); /* The amount of characters of the next label */
	while( LabelCount != 0 )
	{
		if( DNSIsLabelPointerStart(LabelCount) )
		{
			int LabelPointer = 0;
			LabelsLength += 2;
			Redirected = TRUE;
			if( buffer == NULL )
			{
				break;
			}
			LabelPointer = DNSLabelGetPointer(NameItr);
			if( LabelPointer > DNSBodyLength )
			{
				return -1;
			}
			NameItr = DNSBody + DNSLabelGetPointer(NameItr);
		} else {
			if( NameItr + LabelCount > DNSBody + DNSBodyLength )
			{
				return -1;
			}

			if( buffer != NULL )
			{
				if( BufferItr + LabelCount + 1 - buffer <= BufferLength )
				{
					memcpy(BufferItr, NameItr + 1, LabelCount);
				} else {
					if( BufferItr == buffer )
					{
						if( BufferLength > 0 )
						{
							*BufferItr = '\0';
						}
					} else {
						*(BufferItr - 1) = '\0';
					}
					return -1;
				}
			}

			if( Redirected == FALSE )
			{
				LabelsLength += (LabelCount + 1);
			}
			NameItr += (1 + LabelCount);
			if( buffer != NULL )
			{
				BufferItr += LabelCount;
				*BufferItr = '.';
				++BufferItr;
			}
		}

		LabelCount = GET_8_BIT_U_INT(NameItr);
	}

	if( buffer != NULL )
	{
		if( BufferItr == buffer )
		{
			if( BufferLength > 0 )
			{
				*BufferItr = '\0';
			} else {
				return -1;
			}
		} else {
			*(BufferItr - 1) = '\0';
		}
	}

	if( Redirected == FALSE )
	{
		++LabelsLength;
	}

	return LabelsLength;
}

int DNSGetHostNameLength /* including terminated-zero */ (const char *DNSBody, int DNSBodyLength, const char *NameStart)
{
	const char *NameItr = NameStart;
	int NameLength = 0;
	int LabelCount = GET_8_BIT_U_INT(NameItr); /* The amount of characters of the next label */
	while( LabelCount != 0 )
	{
		if( DNSIsLabelPointerStart(LabelCount) )
		{
			if( DNSLabelGetPointer(NameItr) > DNSBodyLength )
			{
				return INT_MAX; /* Error detected */
			}
			NameItr = DNSBody + DNSLabelGetPointer(NameItr);
		} else {
			if( NameItr + LabelCount > DNSBody + DNSBodyLength )
			{
				return INT_MAX; /* Error detected */
			}
			NameLength += (LabelCount + 1);
			NameItr += (1 + LabelCount);
		}

		LabelCount = GET_8_BIT_U_INT(NameItr);

		if( NameLength > DNSBodyLength )
        {
            return INT_MAX; /* Error detected */
        }
	}

	if( NameLength == 0 )
	{
		return 1;
	} else {
		return NameLength;
	}
}

DNSDataInfo DNSParseData(const char *DNSBody,
						int DNSBodyLength,
						const char *DataBody,
						int DataLength,
						void *Buffer,
						int BufferLength,
						const ElementDescriptor *Descriptor,
						int CountOfDescriptor,
						int Num)
{
	DNSDataInfo Result = {DNS_DATA_TYPE_UNKNOWN, 0};

	const char *PendingData = DataBody;

	if( Num > CountOfDescriptor || DataLength <= 0 )
		return Result;

	while(Num != 1)
	{
		switch(Descriptor -> element)
		{
			case DNS_LABELED_NAME:
				PendingData = DNSJumpOverName(PendingData);
				break;

			case DNS_CHARACTER_STRING:
				PendingData += strlen(PendingData) + 1;
				break;

			case DNS_IPV6_ADDR:
				PendingData += 16;
				break;

			case DNS_IPV4_ADDR:
			case DNS_32BIT_UINT:
				PendingData += 4;
				break;

			case DNS_DNSKEY_FLAGS:
			case DNS_16BIT_UINT:
				PendingData += 2;
				break;

			case DNS_DNSKEY_PROTOCOL:
			case DNS_DNSKEY_ALGORITHM:
			case DNS_8BIT_UINT:
				PendingData += 1;
				break;

			default:
				return Result;
				break;
		}

		--Num;
		++Descriptor;
	}

	switch(Descriptor -> element)
	{
		case DNS_LABELED_NAME:
			Result.DataLength = DNSGetHostNameLength(DNSBody, DNSBodyLength, PendingData);
			if( BufferLength < Result.DataLength )
				break;

			DNSGetHostName(DNSBody, INT_MAX, PendingData, (char *)Buffer, INT_MAX);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		case DNS_CHARACTER_STRING:
			if( BufferLength < GET_8_BIT_U_INT(PendingData) + 1 )
			{
				break;
			}

			memcpy(Buffer, PendingData + 1, GET_8_BIT_U_INT(PendingData));
			((char *)Buffer)[GET_8_BIT_U_INT(PendingData)] = '\0';

			Result.DataLength = GET_8_BIT_U_INT(PendingData) + 1;
			Result.DataType = DNS_DATA_TYPE_STRING;

			break;

		case DNS_32BIT_UINT:
			{
				uint32_t Tmp = GET_32_BIT_U_INT(PendingData);
				if(BufferLength < 4)
					break;
				memcpy(Buffer, &Tmp, 4);
				Result.DataLength = 4;
				Result.DataType = DNS_DATA_TYPE_UINT;
			}
			break;

		case DNS_16BIT_UINT:
			{
				uint16_t Tmp = GET_16_BIT_U_INT(PendingData);
				if(BufferLength < 2)
					break;
				memcpy(Buffer, &Tmp, 2);
				Result.DataLength = 2;
				Result.DataType = DNS_DATA_TYPE_UINT;
			}
			break;

		case DNS_DNSKEY_PROTOCOL:
		case DNS_8BIT_UINT:
			if(BufferLength < 1)
				break;
			*(char *)Buffer = *PendingData;
			Result.DataLength = 1;
			Result.DataType = DNS_DATA_TYPE_UINT;
			break;

		case DNS_DNSKEY_FLAGS:
			if( BufferLength < 17 )
			{
				break;
			}

			Result.DataLength = 17;
			BinaryOutput(PendingData, 2, Buffer);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		case DNS_DNSKEY_ALGORITHM:
			{
				const char *Name;

				Name = DNSSECGetAlgorithmName(*PendingData);

				if( BufferLength < strlen(Name) + 1 + 4 )
				{
					break;
				}

				Result.DataLength = sprintf(Buffer, "%d %s", (unsigned char)*PendingData, Name) + 1;
				Result.DataType = DNS_DATA_TYPE_STRING;
			}
			break;

		case DNS_DNSKEY_PUBLIC_KEY:
			if( BufferLength < DataLength - 4 + 1 )
			{
				break;
			}

			Result.DataLength = DataLength - 4 + 1;
			memcpy(Buffer, PendingData, DataLength - 4);
			((char *)Buffer)[DataLength - 4] = '\0';
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		case DNS_DNSSIG_SIGNATURE:
			if( BufferLength < sizeof("(      bytes binary object)") )
			{
				break;
			}

			Result.DataLength = sprintf(Buffer, "(%d bytes binary object)", (int)(DataLength - (PendingData - DataBody)));
			Result.DataType = DNS_DATA_TYPE_STRING;

			break;

		case DNS_IPV4_ADDR:
			if(BufferLength < 16)
				break;
			Result.DataLength =
			sprintf((char *)Buffer, "%u.%u.%u.%u",	GET_8_BIT_U_INT(PendingData),
											GET_8_BIT_U_INT(PendingData + 1),
											GET_8_BIT_U_INT(PendingData + 2),
											GET_8_BIT_U_INT(PendingData + 3)
				);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		case DNS_IPV6_ADDR:
			if(BufferLength < 40)
				break;
			Result.DataLength =
			sprintf((char *)Buffer, "%x:%x:%x:%x:%x:%x:%x:%x",	GET_16_BIT_U_INT(PendingData),
														GET_16_BIT_U_INT(PendingData + 2),
														GET_16_BIT_U_INT(PendingData + 4),
														GET_16_BIT_U_INT(PendingData + 6),
														GET_16_BIT_U_INT(PendingData + 8),
														GET_16_BIT_U_INT(PendingData + 10),
														GET_16_BIT_U_INT(PendingData + 12),
														GET_16_BIT_U_INT(PendingData + 14)

				);
			Result.DataType = DNS_DATA_TYPE_STRING;
			break;

		default:
			break;
	}
	return Result;
}

char *GetAnswer(const char *DNSBody, int DNSBodyLength, const char *DataBody, int DataLength, char *Buffer, DNSRecordType ResourceType)
{
	int loop2;

	int DCount = 0;

	const ElementDescriptor	*Descriptor;

	if( Buffer == NULL )
		return NULL;

	DCount = DNSGetDescriptor(ResourceType, FALSE, &Descriptor);

	if( Descriptor == NULL )
	{
		Buffer += sprintf(Buffer, "   Unparsable type : %d : %s\n", ResourceType, DNSGetTypeName(ResourceType));
	} else {
		char		InnerBuffer[512];
		DNSDataInfo	Data;

		Buffer += sprintf(Buffer, "   %s:", DNSGetTypeName(ResourceType));

		if( DCount != 1 )
		{
			Buffer += sprintf(Buffer, "\n");
		}

		for(loop2 = 0; loop2 != DCount; ++loop2)
		{
			Data = DNSParseData(DNSBody,
								DNSBodyLength,
								DataBody,
								DataLength,
								InnerBuffer,
								sizeof(InnerBuffer),
								Descriptor,
								DCount,
								loop2 + 1);

			if( DCount != 1 )
			{
				if( Descriptor[loop2].description != NULL )
				{
					Buffer += sprintf(Buffer, "      %s:", Descriptor[loop2].description);
				}
			}

			switch(Data.DataType)
			{
				case DNS_DATA_TYPE_INT:
					if(Data.DataLength == 1)
						Buffer += sprintf(Buffer, "%d", (int)*(char *)InnerBuffer);

					if(Data.DataLength == 2)
						Buffer += sprintf(Buffer, "%d", (int)*(int16_t *)InnerBuffer);

					if(Data.DataLength == 4)
						Buffer += sprintf(Buffer, "%u", *(int32_t *)InnerBuffer);

					break;

				case DNS_DATA_TYPE_UINT:
					if(Data.DataLength == 1)
						Buffer += sprintf(Buffer, "%d", (int)*(unsigned char *)InnerBuffer);

					if(Data.DataLength == 2)
						Buffer += sprintf(Buffer, "%d", (int)*(uint16_t *)InnerBuffer);

					if(Data.DataLength == 4)
						Buffer += sprintf(Buffer, "%u", *(uint32_t *)InnerBuffer);

					break;

				case DNS_DATA_TYPE_STRING:
					Buffer += sprintf(Buffer, "%s", InnerBuffer);
					break;

				default:
					break;
			}

			if( Descriptor[loop2].description != NULL )
			{
				Buffer += sprintf(Buffer, "\n");
			}
		}
	}

	return Buffer;
}

char *GetAllAnswers(const char *DNSBody, int DNSBodyLength, char *Buffer, size_t BufferLength)
{
	int		AnswerCount;
	const char	*Itr;
	int		UsedCount;
	DNSRecordType	ResourceType;

	char TempBuffer[1024];
	int RecordLength;

	if( BufferLength < strlen("   And       More ...\n") )
	{
		return NULL;
	}

	AnswerCount = DNSGetAnswerCount(DNSBody) + DNSGetNameServerCount(DNSBody);

	if( AnswerCount == 0 )
	{
		strcpy(Buffer, "   Nothing.\n");
		return Buffer + strlen("   Nothing.\n");
	}

	BufferLength -= strlen("   And       More ...\n");

	UsedCount = 0;

	while(UsedCount != AnswerCount){
		Itr = DNSGetAnswerRecordPosition(DNSBody, UsedCount + 1);

		ResourceType = (DNSRecordType)DNSGetRecordType(Itr);

		RecordLength = GetAnswer(DNSBody, DNSBodyLength, DNSGetResourceDataPos(Itr), DNSGetResourceDataLength(Itr), TempBuffer, ResourceType) - TempBuffer;

		if( RecordLength < BufferLength )
		{
			strcpy(Buffer, TempBuffer);
			BufferLength -= RecordLength;
			Buffer += RecordLength;
		} else {
			break;
		}

		++UsedCount;
	}
	if( UsedCount < AnswerCount )
	{
		Buffer += sprintf(Buffer, "   And %d More ...\n", AnswerCount - UsedCount);
	}
	return Buffer;
}

int DNSExpand(char *DNSBody, int BufferLength)
{
	return -1;
}

void DNSCopyLable(const char *DNSBody, char *here, const char *src)
{
	while( 1 )
	{
		if( DNSIsLabelPointerStart(GET_8_BIT_U_INT(src)) )
		{
			src = DNSBody + DNSLabelGetPointer(src);
		} else {
			*here = *src;

			if( *src == 0 )
			{
				break;
			}

			++here;
			++src;
		}
	}
}

int DNSExpandCName_MoreSpaceNeeded(const char *DNSBody, int DNSBodyLength)
{
	int				AnswerCount	=	DNSGetAnswerCount(DNSBody);
	int				Itr	=	1;
	int				MoreSpaceNeeded = 0;
	const char		*Answer;
	DNSRecordType	Type;
	const char		*Resource;
	int				ResourceLength;

	int				NameLength;

	if( AnswerCount < 1 )
	{
		return 0;
	}

	do
	{
		Answer = DNSGetAnswerRecordPosition(DNSBody, Itr);

		Type = DNSGetRecordType(Answer);
		if( Type == DNS_TYPE_CNAME )
		{
			ResourceLength = DNSGetResourceDataLength(Answer);
			Resource = DNSGetResourceDataPos(Answer);
			NameLength = DNSGetHostNameLength(DNSBody, DNSBodyLength, Resource);
			if( NameLength == INT_MAX )
			{
				return INT_MAX;
			}

			MoreSpaceNeeded += (NameLength + 1) - ResourceLength;
		}

		++Itr;

	}while( Itr <= AnswerCount );

	return MoreSpaceNeeded;
}

/* You should meke sure there is no additional record and nameserver record */
void DNSExpandCName(const char *DNSBody, int DNSBodyLength)
{
	int				AnswerCount	=	DNSGetAnswerCount(DNSBody);
	int				Itr	=	1;
	const char		*Answer;
	DNSRecordType	Type;
	char			*Resource;
	int				ResourceLength;

	int				NameLength;
	char			*NameEnd; /* After terminated-zero */

	char			*DNSEnd;


	if( AnswerCount < 1 )
	{
		return;
	}

	do
	{
		Answer = DNSGetAnswerRecordPosition(DNSBody, Itr);

		Type = DNSGetRecordType(Answer);
		if( Type == DNS_TYPE_CNAME )
		{
			ResourceLength = DNSGetResourceDataLength(Answer);
			Resource = (char *)DNSGetResourceDataPos(Answer);
			NameLength = DNSGetHostNameLength(DNSBody, DNSBodyLength, Resource);
			if( NameLength == INT_MAX )
			{
				return;
			}

			NameEnd = Resource + ResourceLength;

			DNSEnd = (char *)DNSGetAnswerRecordPosition(DNSBody, AnswerCount + 1);

			SET_16_BIT_U_INT(Resource - 2, NameLength + 1);

			memmove(Resource + NameLength + 1, NameEnd, DNSEnd - NameEnd);

			DNSCopyLable(DNSBody, Resource, Resource);
		}

		++Itr;

	}while( Itr <= AnswerCount );
}
