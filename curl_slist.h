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

struct curl_slist *aws_curl_slist_create_nocopy(char **strs);
struct curl_slist *aws_curl_slist_copy(struct curl_slist *list);
struct curl_slist *aws_curl_slist_free(struct curl_slist **list_ptr);
struct curl_slist *aws_curl_slist_sort(int (*compare_f)(const char *, const char *), struct curl_slist *list);
struct curl_slist *aws_curl_slist_sort_inplace(int (*compare_f)(const char *, const char *), struct curl_slist *list);
struct curl_slist *aws_curl_slist_map_data(char *(*map_f)(char *), struct curl_slist *list);
struct curl_slist *aws_curl_slist_fold_left(struct curl_slist *(*fold_f)(struct curl_slist *, char *), struct curl_slist *list1, struct curl_slist *list2);
char *aws_curl_slist_concat(struct curl_slist *list);
char *aws_curl_slist_join_char(char delim, struct curl_slist *list);
void aws_curl_slist_dump(struct curl_slist *list);

#endif /* !LIBAWSCLIENT_CURL_SLIST_H_ */
