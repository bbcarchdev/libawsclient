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

#ifndef LIBAWSCLIENT_CURL_SLIST_H_
# define LIBAWSCLIENT_CURL_SLIST_H_ 1

# include <curl/curl.h>
# include "attributes.h"

const struct curl_slist *aws_curl_slist_create_nocopy(const char * const * const restrict strs);
const struct curl_slist *aws_curl_slist_copy(const struct curl_slist * const nullable restrict list);
const struct curl_slist *aws_curl_slist_free(struct curl_slist * restrict * const nullable restrict list_ptr);

const struct curl_slist *aws_curl_slist_sort(int (* const sort_f)(const char * const restrict, const char * const restrict), const struct curl_slist * const restrict list);
const struct curl_slist *aws_curl_slist_map_data(const char *(* const map_f)(const char * const restrict), const struct curl_slist * const restrict list);
const struct curl_slist *aws_curl_slist_fold_left(mutable struct curl_slist *(* const fold_f)(mutable struct curl_slist * const, const char * const), mutable struct curl_slist * const list1, const struct curl_slist * const list2);
const char *aws_curl_slist_concat(const struct curl_slist * const restrict list);
const char *aws_curl_slist_join_char(const char delim, const struct curl_slist * const restrict list);
void aws_curl_slist_dump(const struct curl_slist * const restrict list);

#endif /* !LIBAWSCLIENT_CURL_SLIST_H_ */
