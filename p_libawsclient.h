/* Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
 *
 * Copyright (c) 2014-2015 BBC
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

#ifndef P_LIBAWSCLIENT_H_
# define P_LIBAWSCLIENT_H_             1

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <time.h>
# include <errno.h>
# include <ctype.h>
# include <syslog.h>
# include <sys/types.h>
# include <curl/curl.h>
# include <liburi.h>

# include "libawsclient.h"

# define AWS_DEFAULT_REGION             "us-east-1"
# define S3_DEFAULT_ENDPOINT            "s3.amazonaws.com"
# define S3_REGIONAL_ENDPOINT_FORMAT    "s3-%s.amazonaws.com"
# define S3_DUALSTACK_ENDPOINT_FORMAT   "s3.dualstack.%s.amazonaws.com"

struct aws_s3_bucket_struct
{
	aws_signature_version version;
	char *bucket;
	char *access;
	char *secret;
	char *endpoint; /* [user [":" pass] "@"] host [":" port] */
	char *basepath;
	char *region;
	char *token;
	void (*logger)(int prio, const char *format, va_list ap);
};

struct aws_request_struct
{
	AWSS3BUCKET *bucket;
	char *resource;
	char *method; /* not copied by curl_easy_setopt < 7.17.0 */
	char *url; /* not copied by curl_easy_setopt < 7.17.0 */
	CURL *ch;
	struct curl_slist *headers; /* not copied by curl_easy_setopt */
	int finalised;
};

int aws_s3_ensure_endpoint_is_specified_(AWSS3BUCKET * const s3);
void aws_s3_logf_(AWSS3BUCKET *s3, int prio, const char *format, ...);

int aws_sign_credentials_are_anonymous(const AWSSIGN * const sign);

int aws_base64_encode_(const void *data, int size, uint8_t *buffer);
uint8_t *aws_base64_decode_(uint8_t *str, void *data, int *datalen);

#endif /*!P_LIBAWSCLIENT_H_*/
