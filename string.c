/**
 * Copyright (c) 2017 BBC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "p_libawsclient.h"

static size_t aws_join_buflen_(size_t delim_strlen, char **list) AWS_PURE;
static char *aws_timenf_(const char *format, size_t length, const time_t *date) AWS_FORMAT_TIME_1 AWS_ALLOC_2 AWS_MALLOC;
static char *aws_vasprintf_(const char * format, va_list args);

/**
 * returns a newly allocated string, or NULL on failure
 */
char *
aws_trim(char c, char * const str)
{
	char *src = str;
	char *dst;
	size_t len;
	if(!str)
	{
		return errno = EINVAL, NULL;
	}
	while(*src == c)
	{
		src++; /* ignore leading chars */
	}
	len = strlen(src);
	while(len && *(src+len) == c)
	{
		len--; /* reduce length if trailing chars match */
	}
	dst = malloc(len + 1);
	if(!dst)
	{
		return errno = ENOMEM, NULL;
	}
	(void) memcpy(dst, src, len);
	*(dst+len) = '\0';
	return dst;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
char *
aws_collapse(char c, char * const str)
{
	char *src = str;
	char *dst, *result;
	if(!str)
	{
		return errno = EINVAL, NULL;
	}
	result = dst = malloc(strlen(str) + 1);
	if(!dst)
	{
		return errno = ENOMEM, NULL;
	}
	for(; (*dst++ = *src); src++)
	{
		if(*src == c)
		{
			while(*(src + 1) == c)
			{
				src++;
			}
		}
	}
	*dst = '\0'; /* don't bother to realloc the buffer */
	return result;
}

char *
aws_strtolower_inplace(char * const str)
{
	char *c = str;
	if(!str)
	{
		return errno = EINVAL, NULL;
	}
	while(*c)
	{
		*c = tolower(*c);
		c++;
	}
	return str;
}

/**
 * list argument can be NULL
 * returns a newly allocated string, or NULL on failure
 */
char *
aws_join_char(char delim, char ** const list)
{
	char **strs = list;
	const size_t length = aws_join_buflen_(1, strs);
	if(!length)
	{
		return strdup("");
	}
	char *s = malloc(length), *ptr = s;
	if(!s)
	{
		return errno = ENOMEM, NULL;
	}
	while(*strs)
	{
		if(ptr != s)
		{
			*ptr++ = delim;
		}
		ptr = aws_stradd(ptr, *strs++);
	}
	return s;
}

/**
 * list can be NULL
 */
static size_t
aws_join_buflen_(const size_t delim_strlen, char ** const list)
{
	char **strs = list;
	size_t length = 0;
	while(*strs)
	{
		length += strlen(*strs++) + delim_strlen;
		/* remove last delimiter and add terminating byte */
		if(!strs)
		{
			length -= delim_strlen - 1;
		}
	}
	return length;
}

char *
aws_stradd(char * const dst, char * const src)
{
#ifdef HAVE_STPCPY
	return stpcpy(dst, src);
#else
	return strchr(strcpy(dst, src), '\0');
#endif
}

/**
 * returns a newly allocated string, or NULL on failure
 */
char *
aws_strf(const char * const format, ...)
{
	char *s;
	va_list args;
	(void) va_start(args, format);
#ifdef HAVE_VASPRINTF
	if(vasprintf(&s, format, args) == -1)
	{
		s = NULL;
	}
#else
	s = aws_vasprintf_(format, args);
#endif
	(void) va_end(args);
	return s;
}

static char *
aws_vasprintf_(const char * const format, va_list args)
{
	const size_t assumed_to_be_big_enough = 128 * 1024;
	char *s = malloc(assumed_to_be_big_enough), *tmp;
	int r;
	if(!s)
	{
		return NULL;
	}
# ifdef HAVE_VSNPRINTF
	r = vsnprintf(s, assumed_to_be_big_enough, format, args);
# else
	r = vsprintf(s, format, args);
# endif
	if(r < 0)
	{
		free(s);
		return NULL;
	}
	*(s + r) = '\0';
	/* attempt to truncate ptr to used length, or just carry on if realloc fails */
	tmp = realloc(s, r + 1);
	if(tmp)
	{
		s = tmp;
	}
	return s;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
char *
aws_timef(const char * const format, const time_t * const time)
{
	/* TODO: it's hard to compute how much space strftime() will need */
	return aws_timenf_(format, 1024, time);
}

/**
 * pass in the maximum length of the output string including terminating byte
 * returns a newly allocated string, or NULL on failure
 */
static char *
aws_timenf_(const char * const format, const size_t length, const time_t * const time)
{
	struct tm brokentime;
	if(!format || !time)
	{
		return errno = EINVAL, NULL;
	}
	if(!gmtime_r(time, &brokentime))
	{
		return NULL;
	}
	return aws_brokentimenf(format, length, &brokentime);
}

/**
 * pass in the maximum length of the output string including terminating byte
 * returns a newly allocated string, or NULL on failure
 */
char *
aws_brokentimenf(const char * const format, const size_t length, struct tm * const brokentime)
{
	char *str;
	if(!format || !brokentime)
	{
		return errno = EINVAL, NULL;
	}
	str = calloc(1, length);
	if(!str)
	{
		return errno = ENOMEM, NULL;
	}
	if(!strftime(str, length, format, brokentime))
	{
		free(str);
		return NULL;
	}
	return str;
}

int
aws_strempty(char *str)
{
	return (!str || strcmp(str, "") == 0);
}
