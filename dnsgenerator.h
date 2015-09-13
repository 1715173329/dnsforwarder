#ifndef _DNS_GENERATOR_H_
#define _DNS_GENERATOR_H_

#include <string.h>
//#include "common.h"
#include "dnsparser.h"

#define SET_16_BIT_U_INT(here, val)	(*(uint16_t *)(here) = htons((uint16_t)(val)))
#define SET_32_BIT_U_INT(here, val)	(*(uint32_t *)(here) = htonl((uint32_t)(val)))

/* Handle DNS header*/
#define DNSSetQueryIdentifier(dns_start, QId)	SET_16_BIT_U_INT((char *)(dns_start), QId)

#define DNSSetFlags(dns_start, Flags)			SET_16_BIT_U_INT((char *)(dns_start) + 2, Flags)

#define DNSSetQuestionCount(dns_start, QC)		SET_16_BIT_U_INT((char *)(dns_start) + 4, QC)

#define DNSSetAnswerCount(dns_start, AnC)		SET_16_BIT_U_INT((char *)(dns_start) + 6, AnC)

#define DNSSetNameServerCount(dns_start, ASC)	SET_16_BIT_U_INT((char *)(dns_start) + 8, ASC)

#define DNSSetAdditionalCount(dns_start, AdC)	SET_16_BIT_U_INT((char *)(dns_start) + 10, AdC)

#define DNSLabelMakePointer(pointer_ptr, location)	(((unsigned char *)(pointer_ptr))[0] = (192 + (location) / 256), ((unsigned char *)(pointer_ptr))[1] = (location) % 256)

extern const char OptPseudoRecord[];
#define	OPT_PSEUDORECORD_LENGTH	11

char *DNSLabelizedName(__inout char *Origin, __in size_t OriginSpaceLength);

int DNSCompress(__inout char *DNSBody, __in int DNSBodyLength);

int DNSGenerateData(__in char *Data,
					__out void *Buffer,
					__in size_t BufferLength,
					__in const ElementDescriptor *Descriptor
					);

char *DNSGenHeader(	__out char			*Buffer,
					__in unsigned short	QueryIdentifier,
					__in DNSFlags		Flags,
					__in unsigned short	QuestionCount,
					__in unsigned short	AnswerCount,
					__in unsigned short	NameServerCount,
					__in unsigned short	AdditionalCount
					);

int DNSGenQuestionRecord(__out char			*Buffer,
						 __in int			BufferLength,
						 __in const char	*Name,
						 __in uint16_t		Type,
						 __in uint16_t		Class
						 );

int DNSGenResourceRecord(	__out char		*Buffer,
							__in int		BufferLength,
							__in const char	*Name,
							__in uint16_t	Type,
							__in uint16_t	Class,
							__in uint32_t	TTL,
							__in const void	*Data,
							__in uint16_t	DataLength,
							__in BOOL		LablelizedData
						   );


#define DNSSetName(here, labeled_name)			(memcpy((here), (labeled_name), strlen(labeled_name) + 1), \
													((char *)here) + strlen(labeled_name) + 1)

#define DNSSetResourceDataLength(ans_start_ptr, len)	SET_16_BIT_U_INT(DNSJumpOverName(ans_start_ptr) + 8, len)

int DNSAppendAnswerRecord(__inout char *OriginBody, __in char *Record, __in int RecordLength);

#define	EDNS_REMOVED	1
#define	EDNS_NO_AR		0
#define EDNS_NOT_EDNS	(-1)
int DNSRemoveEDNSPseudoRecord(char *RequestContent, int *RequestLength);

void DNSAppendEDNSPseudoRecord(char *RequestContent, int *RequestLength);

#endif /* _DNS_GENERATOR_H_ */
