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

#ifndef LIBAWSCLIENT_AWS_STRING_H_
# define LIBAWSCLIENT_AWS_STRING_H_ 1

# include <time.h>
# include "attributes.h"

const char *aws_trim(const char c, const char * const nonnull str) MALLOC;
const char *aws_collapse(const char c, const char * const nonnull str) MALLOC;
const char *aws_strtolower(const char * const nonnull s) MALLOC;
const char *aws_join_char(const char delim, const char * const * const nullable list) MALLOC;
char *aws_stradd(char * const nonnull dst, const char * const nonnull src);
const char *aws_strf(const char * const nonnull format, ...) FORMAT_STRING_1_2 MALLOC;
const char *aws_timef(const char * const nonnull format, const time_t * const nonnull date) FORMAT_TIME_1 MALLOC;
const char *aws_timenf(const char * const nonnull format, const size_t length, const time_t * const nonnull date) FORMAT_TIME_1 ALLOC_2 MALLOC;
const char *aws_brokentimenf(const char * const nonnull format, const size_t length, const struct tm * const nonnull brokentime) FORMAT_TIME_1 ALLOC_2 MALLOC;

#endif /* !LIBAWSCLIENT_AWS_STRING_H_ */
