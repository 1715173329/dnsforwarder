#ifndef _UTILS_
#define _UTILS_

#include <stdlib.h>
#include <stdio.h>

#include "common.h"

#define ROUND_DOWN(val, base)	((val) / (base) * (base))
#define ROUND(val, base)		ROUND_DOWN((val) + (base) / 2, base)
#define ROUND_UP(val, base)		ROUND_DOWN((val) + (base) - 1, base)

typedef int offset_t;

#define CURRENT_THREAD_ID	(GET_THREAD_ID())

/* void *SafeMalloc(size_t Bytes);
 * Description:
 *  Allocate a block of memory of `Bytes' bytes.
 * Parameters:
 *  Bytes:The size of memory to be allocated.
 * Return value:
 *  The first address of the allocated block of memory.
 */
#define SafeMalloc	malloc

/* void SafeFree(void *Memory);
 * Description:
 *  Free a block of memory allocated by SafeMalloc().
 * Parameters:
 *  Memory:The first address of the memory to be freed.
 */
#define SafeFree	free

/* int SafeRealloc(void **Memory_ptr, size_t NewBytes);
 * Description:
 *  Free the memory pointed by `*Memory_ptr', and reallocate a new block of memory of `NewBytes' bytes.
 *  If failed to reallocate, the `*Memory_ptr' will not be changed and `**Memory_ptr' will not be freed.
 *  If successful, the contents of the old memory are be copyed to the new one and `*Memory_ptr' are set to the new memory's address. The old memory are freed.
 * Parameters:
 *  Memory_ptr:The pointer to a variable which is a pointer to the old memory.
 *  NewBytes:New size in bytes.
 * Return Value:
 *  If everything is successful, the function returns 0. Otherwise a non-zero value returned.
 */
int SafeRealloc(void **Memory_ptr, size_t NewBytes);

/* char *StrToLower(char *str);
 * Description:
 *  Lowercase all of the characters in a string.
 * Parameters:
 *  str:The string to be lowercased.
 * Return Value:
 *  The value of `str'.
 */
char *StrToLower(char *str);

/* char *BoolToYesNo(BOOL value);
 * Parameters:
 *  value:A Boolean value.
 * Return Value:
 *  If `value' is equal to FALSE, the function returns a pointer to string "No". Otherwise, "Yes" will be returnd.
 */
char *BoolToYesNo(BOOL value);

int GetModulePath(char *Buffer, int BufferLength);

int GetErrorMsg(int Code, char *Buffer, int BufferLength);

char *GetCurDateAndTime(char *Buffer, int BufferLength);

#ifndef WIN32
int Execute(const char *Cmd);
#endif /* WIN32 */

int	Base64Decode(const char *File);

int IPv6AddressToNum(const char *asc, void *Buffer);

int IPv4AddressToNum(const char *asc, void *Buffer);

sa_family_t GetAddressFamily(const char *Addr);

int IPv6AddressToAsc(const void *Address, void *Buffer);

int	GetConfigDirectory(char *out);

BOOL FileIsReadable(const char *File);

BOOL IsPrime(int n);

int FindNextPrime(int Current);

BOOL ContainWildCard(const char *item);

int ELFHash(const char *str, int Unused);

void HexDump(const char *Data, int Length);

char *BinaryOutput(const char *Origin, int OriginLength, char *Buffer);

char *StringDup(const char *Str);

char *StrNpbrk(char *Str, const char *Ch);

char *StrRNpbrk(char *Str, const char *Ch);

char *GoToNextNonSpace(char *Here);

char *GoToPrevNonSpace(char *Here);

int GetAddressLength(sa_family_t Family);

int SetProgramEnvironment(const char *Name, const char *Value);

int ExpandPath(char *String, int BufferLength);

#endif /* _UTILS_ */
