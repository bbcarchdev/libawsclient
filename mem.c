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

#include <stdlib.h>
#include "mem.h"

void *
aws_safe_free(void ** const restrict ptr)
{
	/* nulling out the pointer before freeing it is safer but slower than, e.g.
	 * https://github.com/curl/curl/blob/master/lib/memdebug.h#L170
	 */
	if(!ptr)
	{
		return NULL;
	}
	void *tmp = *ptr;
	*ptr = NULL;
	(void) free(tmp);
	return NULL;
}

/**
 * free a NULL-terminated array of malloc'd pointers, and NULL out all of
 * their references.
 * returns NULL so can be used
 */
void *
aws_safe_free_list(void *** const restrict list_ptr)
{
	void ***item = list_ptr;
	while(*item)
	{
		(void) aws_safe_free(*item++);
	}
	return NULL;
}
