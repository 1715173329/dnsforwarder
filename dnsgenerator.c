#include <stdio.h>
#include "dnsgenerator.h"
#include "utils.h"
#include "dnsparser.h"

const char OptPseudoRecord[] = {
	0x00,
	0x00, 0x29,
	0x05, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
/*
	0x00, 0x08,
	0x00, 0x08,
	0x00, 0x01,
	0x16, 0x00,
	0x01, 0x01, 0x01, 0x01
*/
};

/* Other Codes */
char *DNSLabelizedName(__inout char *Origin, __in size_t OriginSpaceLength){
	unsigned char *LabelLength = (unsigned char *)Origin;

	if( *Origin == '\0' )
		return Origin + 1;

	if( OriginSpaceLength < strlen(Origin) + 2 )
		return NULL;

	memmove(Origin + 1, Origin, strlen(Origin) + 1);

	*LabelLength = 0;
	while(1){
		++Origin;

		if(*Origin == 0) break;
		if(*Origin != '.') ++(*LabelLength);
		else {
			LabelLength = (unsigned char *)Origin;
			*LabelLength = 0;
		}
	}

	return Origin + 1;
}

/* No checking */
int DNSCompress(__inout char *DNSBody, __in int DNSBodyLength)
{
	char *DNSEnd = DNSBody + DNSBodyLength;
	int AnswerCount;
	int loop;
	char *LastName, *CurName;
	char *LastData;
	char *NameEnd;

	DNSRecordType LastType;

	AnswerCount = DNSGetAnswerCount(DNSBody);
	if(AnswerCount == 0) return DNSBodyLength;

	/* The First Stage */
	LastName = (char *)DNSJumpHeader(DNSBody);
	CurName = (char *)DNSGetAnswerRecordPosition(DNSBody, 1);

	NameEnd = (char *)DNSJumpOverName(CurName);
	DNSLabelMakePointer(CurName, LastName - DNSBody);
	/*
	*(unsigned char *)CurName = 0xC0;
	*(unsigned char *)(CurName + 1) = (unsigned char)(LastName - DNSBody);
	*/
	DNSBodyLength -= (NameEnd - CurName) - 2;
	memmove(CurName + 2, NameEnd, DNSEnd - NameEnd);
	DNSEnd -= (NameEnd - CurName) - 2;

	/* The Second Stage */
	LastData = LastName;
	for(loop = 2; loop <= AnswerCount; ++loop)
	{
		LastName = CurName;
		CurName = (char *)DNSGetAnswerRecordPosition(DNSBody, loop);

		LastType = (DNSRecordType)DNSGetRecordType(LastName);

		if(LastType == DNS_TYPE_CNAME)
		{
			LastData = (char *)DNSGetResourceDataPos(LastName);
		}

		NameEnd = (char *)DNSJumpOverName(CurName);
		DNSLabelMakePointer(CurName, LastData - DNSBody);
		/*
		*(unsigned char *)CurName = 0xC0;
		*(unsigned char *)(CurName + 1) = (unsigned char)(LastData - DNSBody);
		*/
		DNSBodyLength -= (NameEnd - CurName) - 2;
		memmove(CurName + 2, NameEnd, DNSEnd - NameEnd);
		DNSEnd -= (NameEnd - CurName) - 2;

	}

	return DNSEnd - DNSBody;
}

char *DNSGenHeader(	__out char			*Buffer,
					__in uint16_t	QueryIdentifier,
					__in DNSFlags		Flags,
					__in uint16_t	QuestionCount,
					__in uint16_t	AnswerCount,
					__in uint16_t	NameServerCount,
					__in uint16_t	AdditionalCount
					){
	DNSSetQueryIdentifier(Buffer, QueryIdentifier);
	DNSSetFlags(Buffer, *(uint16_t *)&Flags);
	DNSSetQuestionCount(Buffer, QuestionCount);
	DNSSetAnswerCount(Buffer, AnswerCount);
	DNSSetNameServerCount(Buffer, NameServerCount);
	DNSSetAdditionalCount(Buffer, AdditionalCount);
	return DNSJumpHeader(Buffer);
}

int DNSGenQuestionRecord(__out char			*Buffer,
						 __in int			BufferLength,
						 __in const char	*Name,
						 __in uint16_t		Type,
						 __in uint16_t		Class
						 ){
	int NameLen;

	NameLen = strlen(Name);

	if(BufferLength < NameLen + 2 + 2 + 2) return 0;

	strcpy(Buffer, Name);

	if( DNSLabelizedName(Buffer, NameLen + 2) == NULL )
	{
		return 0;
	}

	SET_16_BIT_U_INT(Buffer + NameLen + 2, Type);
	SET_16_BIT_U_INT(Buffer + NameLen + 4, Class);

	return NameLen + 2 + 2 + 2;
}

int DNSGenResourceRecord(	__out char		*Buffer,
							__in int		BufferLength,
							__in const char	*Name,
							__in uint16_t	Type,
							__in uint16_t	Class,
							__in uint32_t	TTL,
							__in const void	*Data,
							__in uint16_t	DataLength,
							__in BOOL		LablelizedData
						   )
{
	int NameLen;
	int	DataNeededLength;

	if(*Name != '\0')
		NameLen = strlen(Name) + 1;
	else
		NameLen = 0;

	if( LablelizedData == TRUE )
	{
		DataNeededLength = DataLength + 1;
	} else {
		DataNeededLength = DataLength;
	}

	if( Buffer != NULL )
	{
		if(BufferLength < NameLen + 1 + 2 + 2 + 4 + 2 + DataNeededLength)
			return 0;

		strcpy(Buffer, Name);

		if( DNSLabelizedName(Buffer, BufferLength) == NULL )
			return 0;

		SET_16_BIT_U_INT(Buffer + NameLen + 1, Type);
		SET_16_BIT_U_INT(Buffer + NameLen + 3, Class);
		SET_32_BIT_U_INT(Buffer + NameLen + 5, TTL);
		SET_16_BIT_U_INT(Buffer + NameLen + 9, DataNeededLength);

		if( Data != NULL && DataLength != 0 )
		{
			memcpy(Buffer + NameLen + 11, Data, DataLength);
		}

		if( LablelizedData == TRUE )
		{
			if( DNSLabelizedName(Buffer + NameLen + 11, DataNeededLength) == NULL )
				return 0;
		}
	}

	return NameLen + 1 + 2 + 2 + 4 + 2 + DataNeededLength;
}

int DNSGenerateData(__in			char				*Data,
					__out			void				*Buffer,
					__in			size_t				BufferLength,
					__in	const	ElementDescriptor	*Descriptor
					)

{
	switch(Descriptor -> element)
	{
		case DNS_LABELED_NAME:
			if( Buffer != NULL )
			{
				if(BufferLength < strlen(Data) + 2) return -1;

				strcpy((char *)Buffer, Data);
				DNSLabelizedName((char *)Buffer, BufferLength);
			}
			return strlen(Data) + 2;
			break;

		case DNS_CHARACTER_STRING:
			if( Buffer != NULL )
			{
				if( BufferLength < strlen(Data) + 1 )
				{
					return -1;
				}

				*(unsigned char *)Buffer = strlen(Data);
				memcpy(((char *)Buffer) + 1, Data, strlen(Data));
			}
			return strlen(Data) + 1;
			break;

		case DNS_32BIT_UINT:
			if( Buffer != NULL )
			{
				int a;

				if(BufferLength < 4) return -1;
				sscanf(Data, "%d", &a);
				SET_32_BIT_U_INT(Buffer, a);

			}
			return 4;
			break;
		case DNS_16BIT_UINT:
			if( Buffer != NULL )
			{
				int a;

				if(BufferLength < 2) return -1;
				sscanf(Data, "%d", &a);
				SET_16_BIT_U_INT(Buffer, a);

			}
			return 2;
			break;
		case DNS_8BIT_UINT:
			if( Buffer != NULL )
			{
				if(BufferLength < 1) return -1;
				*(char *)Buffer = *(char *)Data;
			}
			return 1;
			break;

		case DNS_IPV4_ADDR:
			if( Buffer != NULL )
			{
				int a[4];
				if(BufferLength < 4) return -1;
				sscanf(Data, "%d.%d.%d.%d", a, a + 1, a + 2, a + 3);
				((unsigned char *)Buffer)[0] = a[0];
				((unsigned char *)Buffer)[1] = a[1];
				((unsigned char *)Buffer)[2] = a[2];
				((unsigned char *)Buffer)[3] = a[3];

			}
			return 4;
			break;
		case DNS_IPV6_ADDR:
			if( Buffer != NULL )
			{
				int a[8];
				if(BufferLength < 16) return -1;
				sscanf(Data, "%x:%x:%x:%x:%x:%x:%x:%x",
						a, a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7
						);
				SET_16_BIT_U_INT((uint16_t *)Buffer, a[0]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 1, a[1]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 2, a[2]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 3, a[3]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 4, a[4]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 5, a[5]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 6, a[6]);
				SET_16_BIT_U_INT((uint16_t *)Buffer + 7, a[7]);

			}
			return 16;
			break;
		default:
			return 0;
			break;
	}
}

int DNSAppendAnswerRecord(__inout char *OriginBody, __in char *Record, __in int RecordLength)
{
	memcpy((void *)DNSJumpOverAnswerRecords(OriginBody), Record, RecordLength);
	DNSSetAnswerCount(OriginBody, DNSGetAnswerCount(OriginBody) + 1);
	return DNSJumpOverAnswerRecords(OriginBody) - OriginBody + RecordLength;
}

int DNSRemoveEDNSPseudoRecord(char *RequestContent, int *RequestLength)
{
	if( DNSGetAdditionalCount(RequestContent) == 1 )
	{
		const char *AdditionalRecords;
		AdditionalRecords = DNSJumpOverQuestionRecords(RequestContent);
		if( DNSGetRecordType(AdditionalRecords) == DNS_TYPE_OPT )
		{
			DNSSetAdditionalCount(RequestContent, 0);
			*RequestLength -= (11 + AdditionalRecords[10]);

			return EDNS_REMOVED;
		} else {
			return EDNS_NOT_EDNS;
		}
	} else {
		return EDNS_NO_AR;
	}
}

void DNSAppendEDNSPseudoRecord(char *RequestContent, int *RequestLength)
{
	memcpy((char *)RequestContent + *RequestLength, OptPseudoRecord, OPT_PSEUDORECORD_LENGTH);
	DNSSetAdditionalCount(RequestContent, 1);
	*RequestLength += OPT_PSEUDORECORD_LENGTH;
}
