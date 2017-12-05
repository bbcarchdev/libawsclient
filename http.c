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

#include <alloca.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "http.h"

#include "aws_string.h"
#include "curl_slist.h"
#include "mem.h"

#define HTTP_DATE_FORMAT "%a, %d %b %Y %H:%M:%S GMT"
#define HTTP_DATE_LENGTH 29

/**
 * modifies and returns the input list (which can be NULL). if the header
 * name already exists, the value of the first occurrence is replaced by the
 * argument and subsequent occurrences are removed. if the header name is not
 * present, the supplied header is appended to the end of the list.
 * returns NULL on failure or a pointer to the first item of the (modified)
 * input list on success.
 * data within the original input list may have been free()d.
 */
struct curl_slist *
aws_set_http_header(
	struct curl_slist * restrict headers,
	char * restrict header
) {
	int found = 0;
	struct curl_slist *current = headers, *prev = NULL, *next;
	/* get the length of the header name + colon */
	const size_t len = aws_http_header_name_length(header) + 1;
	if(len <= 1)
	{
		return NULL;
	}
	while(current)
	{
		if(current->data && strncasecmp(current->data, header, len) == 0)
		{
			/* existing header of same name found */
			(void) aws_safe_free((void **) &current->data);
			if(found)
			{
				/* we've already found one of these headers, delete this one from the list */
				if(prev)
				{
					prev->next = current->next;
				}
				next = current->next;
				(void) aws_safe_free((void **) &current);
				current = next;
				continue;
			}
			/* we haven't found this header before, replace this one's data */
			current->data = strdup(header);
			if (!current->data)
			{
				return NULL;
			}
			found = 1;
		}
		prev = current;
		current = current->next;
	}
	/* if we replaced an existing header we're done, otherwise append the new header */
	if(found)
	{
		return headers;
	}
	return curl_slist_append(headers, header);
}

/**
 * returns a copy of the input list but with the new header set. if the header
 * name already exists, the value of the first occurrence is replaced by the
 * argument and subsequent occurrences are removed. if the header name is not
 * present, the supplied header is appended to the end of the list.
 * returns NULL on failure or a pointer to the first item of the (modified)
 * input list on success.
 * dispose of with aws_curl_slist_free().
 */
struct curl_slist *
list_with_http_header(
	struct curl_slist * const restrict headers,
	char * const restrict header
) {
	return aws_set_http_header(aws_curl_slist_copy(headers), header);
}

/**
 * allocates and returns a string containing the name (verbatim) of
 * the passed HTTP header. dispose of with free().
 * returns NULL on failure (including no ':' in input string)
 */
char *
aws_http_header_name(char * const header)
{
	const size_t len = aws_http_header_name_length(header);
	if(!len)
	{
		return NULL;
	}
	char *name = malloc(len + 1);
	(void) memcpy(name, header, len);
	*(name+len) = '\0';
	return name;
}

/**
 * allocates a new string
 */
char *
aws_http_header_value(char * const header)
{
	const size_t name_len = aws_http_header_name_length(header);
	if(!name_len)
	{
		return NULL;
	}
	return strdup(header + name_len + 1);
}

size_t
aws_http_header_name_length(char * const header)
{
	ptrdiff_t len;
	if(!header)
	{
		return 0;
	}
	len = strchr(header, ':') - header;
	if(len < 0)
	{
		return 0;
	}
	return len;
}

/**
 * returns NULL on failure
 */
char *
aws_create_http_date_header(const time_t * const timestamp)
{
	char *date, *h;
	date = aws_http_date(timestamp);
	if(!date)
	{
		return NULL;
	}
	h = aws_strf("Date: %s", date);
	(void) free(date);
	return h;
}

/**
 * allocate and return a string containing a HTTP-compatible string conversion
 * of the provided datetime
 *
 * if the current locale could be validated as "C" or "en" in a thread-safe
 * manner, this function could be as simple as:
 *   return aws_timef(HTTP_DATE_FORMAT, timestamp);
 * (see https://www.gnu.org/software/libc/manual/html_node/Setting-the-Locale.html)
 *
 * Even if the current locale is unchanged from the launch value of "C", that
 * global can only be read by calling setlocale(LC_TIME, NULL), which in some
 * implementations is still multithread-unsafe, e.g.
 * BSD: https://github.com/freebsd/freebsd/blob/master/lib/libc/locale/setlocale.c
 * Darwin: https://opensource.apple.com/source/Libc/Libc-320.1.3/locale/FreeBSD/setlocale.c.auto.html
 * glibc is thread-safe:
 * http://sourceware.org/git/?p=glibc.git;a=blob;f=locale/setlocale.c;hb=HEAD
 */
char *
aws_http_date(const time_t * const timestamp)
{
	struct tm time;
	if(!timestamp)
	{
		return NULL;
	}
	if(!gmtime_r(timestamp, &time))
	{
		return NULL;
	}
	return aws_http_date_tm(&time);
}

char *
aws_http_date_tm(struct tm * const time)
{
	/* replace %a and %b in date format string - avoids changing the global locale to "C" */
	const char * const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	const char * const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	char *src = HTTP_DATE_FORMAT, *dst, *fmt;
	if(!time)
	{
		return NULL;
	}
	dst = fmt = alloca(strlen(HTTP_DATE_FORMAT) + 3);
	while(*src)
	{
		if(*src == '%' && *(src+1) == 'a')
		{
			(void) memcpy(dst, days[time->tm_wday], 3);
			src += 2;
			dst += 3;
		}
		else if(*src == '%' && *(src+1) == 'b')
		{
			(void) memcpy(dst, months[time->tm_mon], 3);
			src += 2;
			dst += 3;
		}
		else
		{
			*dst++ = *src++;
		}
	}
	*dst = '\0';
	return aws_brokentimenf(fmt, HTTP_DATE_LENGTH + 1, time);
}
