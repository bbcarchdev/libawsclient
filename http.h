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

#ifndef LIBAWSCLIENT_HTTP_H_
# define LIBAWSCLIENT_HTTP_H_ 1

# include <curl/curl.h>
# include "libawsclient.h"

struct curl_slist *aws_set_http_header(struct curl_slist *headers, char *header);
char *aws_http_header_name(char *header) MALLOC;
char *aws_http_header_value(char *header) MALLOC;
size_t aws_http_header_name_length(char *header) PURE;
char *aws_create_http_date_header(const time_t *timestamp) MALLOC;
char *aws_http_date(const time_t *timestamp) MALLOC;
char *aws_http_date_tm(struct tm *time) MALLOC;

#endif /* !LIBAWSCLIENT_HTTP_H_ */
