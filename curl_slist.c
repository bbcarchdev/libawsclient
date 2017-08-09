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

#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "curl_slist.h"
#include "aws_string.h"
#include "mem.h"

static struct curl_slist *aws_curl_slist_append_nocopy_(struct curl_slist * const nullable restrict list, const char * const restrict data);
static struct curl_slist *aws_curl_slist_get_last_(const struct curl_slist * const nullable restrict list);
static const struct curl_slist *curl_slist_sort_(int (* const compare_f)(const char * nonnull, const char * nonnull), mutable struct curl_slist * restrict list);
static int curl_slist_count_(const struct curl_slist * const restrict list) PURE;
static int curl_slist_total_strlen_(const struct curl_slist * const restrict list) PURE;

/**
 * create a new curl slist from the passed in, null-terminated array of
 * strings, in the order given. Takes ownership of each string.
 * dispose of result by passing to aws_curl_slist_free().
 * returns a pointer to the new list or NULL on failure, at which point
 * none or some of the strings may have been freed.
 *
 * DO NOT pass the same string pointer in twice in the list!
 * This will result in a double-free when freeing the list.
 */
const struct curl_slist *
aws_curl_slist_create_nocopy(const char * const * const restrict strs)
{
	const char * const *data = strs;
	struct curl_slist *list = NULL, *tmp;
	while(*data) {
		tmp = list;
		list = aws_curl_slist_append_nocopy_(list, *data);
		if(!list) return aws_curl_slist_free(&tmp);
		data++;
	}
	return list;
}

/**
 * creates a new curl slist item and takes ownership of the passed-in data
 * simplified from https://github.com/curl/curl/blob/master/lib/slist.c
 */
static struct curl_slist *
aws_curl_slist_append_nocopy_(struct curl_slist * const nullable list, const char * const restrict data)
{
	struct curl_slist *new_item, *last;
	new_item = malloc(sizeof(struct curl_slist));
	if(!new_item)
		return errno = ENOMEM, NULL;
	new_item->data = (char *) data;
	new_item->next = NULL;
	/* if this is the first item, then new_item *is* the list */
	if(!list)
		return new_item;
	last = aws_curl_slist_get_last_(list);
	last->next = new_item;
	return list;
}

/**
 * returns last node in linked list
 * simplified from https://github.com/curl/curl/blob/master/lib/slist.c
 */
static struct curl_slist *
aws_curl_slist_get_last_(const struct curl_slist * const nullable restrict list)
{
	struct curl_slist *item = (struct curl_slist *) list;
	while(item->next) {
		item = item->next;
	}
	return item;
}

/**
 * duplicate a linked list. returns the address of the first record of the
 * cloned list, or NULL in case of an error (or if the input list was NULL).
 *
 * copied from https://github.com/curl/curl/blob/master/lib/slist.c
 * this is also the algorithm described at the end of the C example section of
 * https://en.wikipedia.org/wiki/Tail_call#Tail_recursion_modulo_cons
 * but via calls to curl_slist_append() rather than calling malloc directly.
 */
const struct curl_slist *
aws_curl_slist_copy(const struct curl_slist * const nullable restrict list)
{
	struct curl_slist *inlist = (struct curl_slist *) list, *outlist = NULL, *tmp;
	while(inlist && inlist->data) {
		tmp = curl_slist_append(outlist, inlist->data);
		if(!tmp) return aws_curl_slist_free(&outlist);
		outlist = tmp;
		inlist = inlist->next;
	}
	return outlist;
}

/**
 * thread-safe replacement for curl_slist_free_all()
 * this takes a pointer to the list pointer and NULLs it out.
 * it also NULLs out all of the data pointers before freeing them.
 * this allows it to work with __attribute__((cleanup))
 * returns NULL for convenience as a tail call or unwanted argument.
 */
const struct curl_slist *
aws_curl_slist_free(struct curl_slist * restrict * const nullable restrict list_ptr)
{
	struct curl_slist *item, *next;

	if(!list_ptr || *list_ptr == NULL) return NULL;

	item = *list_ptr;
	*list_ptr = NULL;
	while(item) {
		next = item->next;
		aws_safe_free((void **) &item->data);
		aws_safe_free((void **) &item);
		item = next;
	}
	return NULL;
}

/**
 * allocates and returns a new list with the result of applying the mapping
 * function given to each of the data strings in the supplied slist.
 * the provided function MUST return a newly allocated string, as it will be
 * duplicated and free()d as the list is processed (future versons of this may
 * simply assume ownership of the string returned by the mapping function).
 * If the mapping function returns NULL at any point, processing is terminated
 * and a truncated list is returned. compare list lengths to see if this has
 * occurred.
 * dispose of the result via aws_curl_slist_free().
 * returns NULL on failure.
 */
const struct curl_slist *
aws_curl_slist_map_data(
	const char *(* const map_f)(const char * const restrict),
	const struct curl_slist * const restrict list
) {
	const struct curl_slist *item = list;
	struct curl_slist *list2 = NULL;
	while(item && item->data) {
		char *data = (char *) map_f(item->data);
		if(!data) break;
		list2 = curl_slist_append(list2, data);
		(void) aws_safe_free((void **) &data);
		item = item->next;
	}
	return list2;
}

/**
 * fold the data from the second curl slist into the accumulator list
 * using the fold function given. the second list can be NULL.
 *
 * the fold function should modify the input list rather than allocate
 * a new list, as the latter will result in memory leaks.
 * the arguments to the fold function are also unrestricted - the string
 * pointer may already be referenced by the list.
 */
const struct curl_slist *
aws_curl_slist_fold_left(
	mutable struct curl_slist *(* const fold_f)(mutable struct curl_slist *, const char *),
	mutable struct curl_slist *list1,
	const struct curl_slist * const nullable list2
) {
	struct curl_slist *item = (struct curl_slist *) list2;
	while(item) {
		list1 = fold_f(list1, item->data);
		item = item->next;
	}
	return list1;
}

/**
 * returns a newly allocated list sorted according to the provided string
 * comparison function. dispose of result with aws_curl_slist_free()
 * returns NULL on failure or if given a NULL input list
 */
const struct curl_slist *
aws_curl_slist_sort(
	int (* const compare_f)(const char * nonnull restrict, const char * nonnull restrict),
	const struct curl_slist * const restrict list
) {
	return curl_slist_sort_(compare_f, (struct curl_slist *) aws_curl_slist_copy(list));
}

/**
 * smoke and mirrors.
 * sort the list using the provided string comparison function.
 * this function may return a different first item, but does not allocate a new list
 *
 * the comparison function's string arguments are not declared 'restrict' as
 * it is OK to compare a string against part or all of itself.
 */
static const struct curl_slist *
curl_slist_sort_(
	int (* const compare_f)(const char * nonnull, const char * nonnull),
	mutable struct curl_slist * restrict list
) {
	/*
	by design, this sorts the list in-place by changing the "next" pointers.
	swapping data pointers could leave functions earlier in the stack with
	pointers to items containing different values than they were expecting.

	the algorithm used is bubblesort, which is quick to author, but slow to execute.
	a faster linked-list sort using mergesort is available from
	https://www.chiark.greenend.org.uk/~sgtatham/algorithms/listsort.html
	but the time has not been spent to adapt that code for the curl_slist struct.
	*/

	struct curl_slist *item1, *item2, *previous, *next;
	int sorted = 0;

	if(!list || !list->next) return list;
	while(!sorted) {
		sorted = 1;
		item1 = list, item2 = list->next, previous = NULL;
		while(item1 && item1->data && item2 && item2->data) {
			if(item1->data != item2->data && compare_f(item1->data, item2->data) > 0) {
				// swap items, advance next but keep old prev, flag list as unsorted
				if(list == item1) list = item2;
				if(previous) previous->next = item2;
				next = item2->next;
				item2->next = item1;
				item1->next = next;
				previous = item2;
				item2 = next;
				sorted = 0;
			} else {
				// advance prev and next
				previous = item1;
				item1 = item2;
				item2 = item2->next;
			}
		}
	}

	return list;
}

const char *
aws_curl_slist_concat(const struct curl_slist * const restrict list)
{
	struct curl_slist *item = (struct curl_slist *) list;
	size_t len = curl_slist_total_strlen_(list) + 1;
	char *s = malloc(len), *dst;
	if(!s) return NULL;
	dst = s;
	while(item) {
		if(item->data)
			dst = aws_stradd(dst, item->data);
		item = item->next;
	}
	return s;
}

const char *
aws_curl_slist_join_char(const char delim, const struct curl_slist *list)
{
	size_t len = curl_slist_total_strlen_(list) + curl_slist_count_(list);
	char *s = malloc(len), *dst;
	if(!s) return NULL;
	dst = s;
	while(list) {
		if(list->data) {
			if(dst != s)
				*dst++ = delim;
			dst = aws_stradd(dst, list->data);
		}
		list = list->next;
	}
	return s;
}

static int
curl_slist_count_(const struct curl_slist *list)
{
	int i = 0;
	while(list) {
		i++;
		list = list->next;
	}
	return i;
}

static int
curl_slist_total_strlen_(const struct curl_slist *list)
{
//	fold(+, 0, map(strlen, list))
	int i = 0;
	while(list) {
		if(list->data)
			i += strlen(list->data);
		list = list->next;
	}
	return i;
}

void
aws_curl_slist_dump(const struct curl_slist * const restrict list)
{
	struct curl_slist *item = (struct curl_slist *) list;
	(void) fprintf(stderr, "curl string list: (%p)\n", list);
	while(item && item->data) {
		(void) fprintf(stderr, "* %s\n", item->data);
		item = item->next;
	}
}
