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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aws_string.h"
#include "attributes.h"
#include "mem.h"

#define VASPRINTF_AVAILABLE		(defined(HAVE_VASPRINTF) || _BSD_SOURCE || _GNU_SOURCE)
#define VSNPRINTF_AVAILABLE		(defined(HAVE_VSNPRINTF) || _BSD_SOURCE || _XOPEN_SOURCE >= 500 || _ISOC99_SOURCE || _POSIX_C_SOURCE >= 200112L)
#define STPCPY_AVAILABLE		(defined(HAVE_STPCPY) || _BSD_SOURCE || _GNU_SOURCE || _XOPEN_SOURCE >= 700 || _POSIX_C_SOURCE >= 200809L)

static size_t aws_join_buflen_(const size_t delim_strlen, const char * const * const nullable list) PURE;

/**
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_trim(const char c, const char * const str)
{
	if(!str) return NULL;

	const char *src = str;
	while(*src == c) src++; // ignore leading chars
	size_t len = strlen(src);
	while(len && *(src+len) == c) len--; // reduce length if trailing chars match
	char *value = malloc(len + 1);
	if(!value) return NULL;
	(void) memcpy(value, src, len); // copy bytes
	*(value+len) = '\0';
	return value;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_collapse(const char c, const char * const str)
{
	if(!str) return NULL;

	char *dst = malloc(strlen(str) + 1), *result = dst;
	if(!dst) return NULL;

	const char *src = str;
	for(; (*dst++ = *src); src++) {
		if(*src == c)
			while(*(src + 1) == c)
				src++;
	}
	*dst = '\0'; // don't bother to realloc the string
	return result;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_strtolower(const char * const str)
{
	if(!str) return NULL;

	const size_t length = strlen(str) + 1;
	char *dst = malloc(length);
	if(!dst) return NULL;

	const char *src = str;
	char * const start = dst, * const end = start + length;
	do *dst++ = tolower(*src++);
	while(dst < end);
	return start;
}

/**
 * list argument can be NULL
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_join_char(const char delim, const char * const * const nullable list)
{
	const char * const *strs = list;
	const size_t length = aws_join_buflen_(1, strs);
	if(!length) return strdup("");

	char * const s = malloc(length), *ptr = s;
	if(!s) return NULL;
	while(*strs) {
		if(ptr != s) *ptr++ = delim;
		ptr = aws_stradd(ptr, *strs++);
	}
	return s;
}

/**
 * list can be NULL
 */
static size_t
aws_join_buflen_(const size_t delim_strlen, const char * const * const nullable list)
{
	const char * const *strs = list;
	size_t length = 0;
	while(*strs) {
		length += strlen(*strs++) + delim_strlen;
		// remove last delimiter and add terminating byte
		if(!strs) length -= delim_strlen - 1;
	}
	return length;
}

char *
aws_stradd(char * const dst, const char * const src)
{
#if STPCPY_AVAILABLE
	return stpcpy(dst, src);
#else
	return strchr(strcpy(dst, src), '\0');
#endif
}

/**
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_strf(const char * const format, ...)
{
	char *s;
	int r;
	va_list args;
	(void) va_start(args, format);
#if VASPRINTF_AVAILABLE
	r = vasprintf(&s, format, args);
	if(r == -1) s = NULL;
#else
	const size_t assumed_to_be_big_enough = 128 * 1024;
	s = malloc(assumed_to_be_big_enough);
	if(s) {
# if VSNPRINTF_AVAILABLE
		r = vsnprintf(s, assumed_to_be_big_enough, format, args);
# else
		r = vsprintf(s, format, args);
# endif
		if(r < 0) (void) aws_safe_free((void **) &s);
		else {
			// truncate ptr to used length
			char *tmp = realloc(s, r + 1);
			if(!tmp) (void) aws_safe_free((void **) &s); // TODO: should this just return the large ptr?
			else {
				s = tmp;
				*(s + r) = '\0';
			}
		}
	}
#endif
	(void) va_end(args);
	return s;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_timef(const char * const format, const time_t * const time)
{
	// TODO: it's hard to compute how much space strftime() will need
	return aws_timenf(format, 1024, time);
}

/**
 * pass in the maximum length of the output string including terminating byte
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_timenf(const char * const format, const size_t length, const time_t * const time)
{
	if(!format || !time) return NULL;

	struct tm brokentime;
	if(!gmtime_r(time, &brokentime))
		return NULL;

	return aws_brokentimenf(format, length, &brokentime);
}

/**
 * pass in the maximum length of the output string including terminating byte
 * returns a newly allocated string, or NULL on failure
 */
const char *
aws_brokentimenf(const char * const format, const size_t length, const struct tm * const brokentime)
{
	if(!format || !brokentime) return NULL;

	char * const str = malloc(length);
	if(!str) return NULL;
	if(!strftime(str, length, format, brokentime))
		(void) aws_safe_free((void **) &str);
	return str;
}
