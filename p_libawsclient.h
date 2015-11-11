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

# ifdef WITH_COMMONCRYPTO
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonCrypto.h>
# else
#  include <openssl/hmac.h>
#  include <openssl/evp.h>
#  include <openssl/bio.h>
#  include <openssl/buffer.h>
# endif

# include "libawsclient.h"

# define S3_DEFAULT_ENDPOINT            "s3.amazonaws.com"

struct aws_s3_bucket_struct
{
	char *bucket;
	char *access;
	char *secret;
	char *endpoint;
	char *basepath;
	void (*logger)(int prio, const char *format, va_list ap);
};

struct aws_request_struct
{
	AWSS3BUCKET *bucket;
	char *resource;
	char *method;
	char *url;
	CURL *ch;
	struct curl_slist *headers;
	int finalised;
};

void aws_s3_logf_(AWSS3BUCKET *bucket, int prio, const char *format, ...);

int aws_base64_encode_(const void *data, int size, uint8_t * buffer);
uint8_t *aws_base64_decode_(uint8_t * str, void *data, int *datalen);

#endif /*!P_LIBAWSCLIENT_H_*/
