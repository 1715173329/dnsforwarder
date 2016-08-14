#include <string.h>
#include "stringlist.h"
#include "utils.h"

static int Divide(char *Str, const char *Delimiters)
{
	int		Count = 0;
	char	*Itr;

	if( Delimiters == NULL )
    {
        Delimiters = "";
    }

	Itr = strpbrk(Str, Delimiters);
	while( Itr != NULL )
    {
        *Itr = '\0';

        ++Itr;
		++Count;

		Itr = strpbrk(Itr, Delimiters);
    }

	return Count + 1;
}

static int StringList_Count(StringList *s)
{
    StringListIterator    i;
    const char            *b;
    int                   ret = 0;

    if( StringListIterator_Init(&i, s) != 0 )
    {
        return -1;
    }

    b = i.Next(&i);
    while( b != NULL )
    {
        ++ret;

        b = i.Next(&i);
    }

    return ret;
}

static void *StringList_Add(StringList *s,
                          const char *str,
                          const char *Delimiters
                          )
{
    StableBuffer *sb;

    sb = &(s->Buffer);

    void *Here = sb ->Add(sb, str, strlen(str) + 1);
    if( Here == NULL )
    {
        return NULL;
    }

    Divide(Here, Delimiters);

    return Here;
}

/* Unsafe operation */
static int StringList_AppendLast(StringList *s,
                                 const char *str,
                                 const char *Delimiters
                                 )
{
    StableBuffer            *sb;
    StableBufferIterator    i;
    char                    *b;

    char *l;
    int Used;

    int StrLength; /* Including terminated-0 */
    int LastHalfLength;
    char *NewStr;
    char *NewlyAdded;

    if( s == NULL )
    {
        return -1;
    }

    sb = &(s->Buffer);

    if( StableBufferIterator_Init(&i, sb) != 0 )
    {
        return -2;
    }

    b = i.ToLast(&i);
    if( b == NULL )
    {
        return -3;
    }

    Used = i.CurrentBlockUsed(&i);
    for( l = b + Used - 2; l > b; --l )
    {
        if( *l == '\0' )
        {
            ++l;
            break;
        }
    }

    if( l <= b )
    {
        l = b;
    }

    StrLength = strlen(str) + 1; /* Including terminated-0 */
    LastHalfLength = Used - (l - b); /* Including terminated-0 */
    NewStr = SafeMalloc(StrLength + LastHalfLength - 1);
    if( NewStr == NULL )
    {
        return -4;
    }

    strcpy(NewStr, l);
    strcat(NewStr, str);

    i.RemoveLastNBytesOfCurrentBlock(&i, LastHalfLength);

    NewlyAdded = sb->Add(sb, NewStr, StrLength + LastHalfLength - 1);

    SafeFree(NewStr);

    if( NewlyAdded == NULL )
    {
        return -5;
    }

    return Divide(NewlyAdded, Delimiters);
}

static const char **StringList_ToCharPtrArray(StringList *s)
{
    const char  **ret;
    int         Index = 0;

    StringListIterator    i;
    const char  *ci;

    if( StringListIterator_Init(&i, s) != 0 )
    {
        return NULL;
    }

    ret = SafeMalloc(StringList_Count(s) * sizeof(const char *));
    if( ret == NULL )
    {
        return NULL;
    }

    ci = i.Next(&i);
    while( ci != NULL )
    {
        ret[Index] = ci;
        ++Index;

        ci = i.Next(&i);
    }

    return ret;
}



static void StringList_Clear(StringList *s)
{
    s->Buffer.Clear(&(s->Buffer));
}

static void StringList_Free(StringList *s)
{
    s->Buffer.Free(&(s->Buffer));
}

int StringList_Init(__in StringList *s,
                    __in const char *ori,
                    __in const char *Delimiters
                    )
{
    StableBuffer *sb;

	if( s == NULL )
    {
        return -1;
    }

    sb = &(s->Buffer);

    if( StableBuffer_Init(sb) != 0 )
    {
        return -2;
    }

    s->Count = StringList_Count;
    s->Add = StringList_Add;
    s->AppendLast = StringList_AppendLast;
    s->ToCharPtrArray = StringList_ToCharPtrArray;
    s->Clear = StringList_Clear;
    s->Free = StringList_Free;

	if( ori != NULL )
	{
        void *Here = sb ->Add(sb, ori, strlen(ori) + 1);
        if( Here == NULL )
        {
            sb->Free(sb);
            return -3;
        }

		return Divide(Here, Delimiters);
	} else {
	    return 0;
	}
}

/**
  Iterator Implementation
*/

static const char *StringListIterator_Next(StringListIterator *i)
{
    if( i->CurrentPosition == NULL )
    {
        i->BufferIterator.Reset(&(i->BufferIterator));
        i->CurrentPosition = i->BufferIterator.NextBlock(&(i->BufferIterator));
    } else {
        i->CurrentPosition += strlen(i->CurrentPosition) + 1;
    }

    while(TRUE)
    {
        if( i->CurrentPosition == NULL )
        {
            return NULL;
        } else if( i->BufferIterator.IsInCurrentBlock(&(i->BufferIterator),
                                                      i->CurrentPosition)
                 )
        {
            return i->CurrentPosition;
        }

        i->CurrentPosition = i->BufferIterator.NextBlock(&(i->BufferIterator));
    }
}

static void StringListIterator_Reset(StringListIterator *i)
{
    i->CurrentPosition = NULL;
}

int StringListIterator_Init(StringListIterator *i, StringList *l)
{
    if( i == NULL || l == NULL )
    {
        return -1;
    }

    if( StableBufferIterator_Init(&(i->BufferIterator), &(l->Buffer)) != 0 )
    {
        return -2;
    }

    i->CurrentPosition = NULL;

    i->Next = StringListIterator_Next;
    i->Reset = StringListIterator_Reset;

    return 0;
}
