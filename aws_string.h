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

# include "libawsclient.h"

# include <time.h>

char *aws_trim(char c, char *str) MALLOC;
char *aws_collapse(char c, char *str) MALLOC;
char *aws_strtolower_inplace(char *str);
char *aws_join_char(char delim, char **list) MALLOC;
char *aws_stradd(char *dst, char *src);
char *aws_strf(const char *format, ...) FORMAT_STRING_1_2 MALLOC;
char *aws_timef(const char *format, const time_t *date) FORMAT_TIME_1 MALLOC;
char *aws_brokentimenf(const char *format, size_t length, struct tm *brokentime) FORMAT_TIME_1 ALLOC_2 MALLOC;
int aws_strempty(char *str);

#endif /* !LIBAWSCLIENT_AWS_STRING_H_ */
