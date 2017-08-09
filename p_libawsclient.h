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
# include "attributes.h"

# define AWS_DEFAULT_REGION             "us-east-1"
# define S3_DEFAULT_ENDPOINT            "s3.amazonaws.com"
# define S3_REGIONAL_ENDPOINT_FORMAT    "s3-%s.amazonaws.com"
# define S3_DUALSTACK_ENDPOINT_FORMAT   "s3.dualstack.%s.amazonaws.com"

typedef enum
{
	AWS_ALG_DEFAULT = 0,
	AWS_ALG_SHA1,
	AWS_ALG_HMAC_SHA256
} aws_signature_algorithm_t;

struct aws_signature_params_struct
{
	aws_signature_algorithm_t alg;
	size_t size;
	time_t timestamp;
	aws_request_method_t method; // duplicate of request.method
	aws_s3_resource_key_t resource; // duplicate of request.resource
	aws_access_key_t access_key; // duplicate of request.bucket.access
	aws_secret_key_t secret_key; // duplicate of request.bucket.secret
	aws_session_token_t token; // duplicate of request.bucket.token
	aws_region_t region; // duplicate of request.bucket.region
	const char *service; // used to build the v4 signature string
	const char *payloadhash;
};

struct aws_s3_bucket_struct
{
	aws_signature_version_t ver;
	aws_s3_bucket_name_t bucket;
	aws_access_key_t access;
	aws_secret_key_t secret;
	aws_s3_bucket_endpoint_t endpoint; // host [":" port]
	aws_s3_bucket_basepath_t basepath;
	aws_region_t region;
	aws_session_token_t token;
	void (*logger)(int prio, const char *format, va_list ap);
};

struct aws_request_struct
{
	aws_mutable_s3_bucket_t bucket;
	aws_s3_resource_key_t resource;
	aws_request_method_t method; // not copied by curl_easy_setopt < 7.17.0
	char *url; // not copied by curl_easy_setopt < 7.17.0
	CURL *ch;
	aws_mutable_header_list_t headers; // not copied by curl_easy_setopt
	int finalised;
};

void aws_s3_logf_(aws_mutable_s3_bucket_t bucket, int prio, const char *format, ...);

int aws_base64_encode_(const void *data, int size, uint8_t * buffer);
uint8_t *aws_base64_decode_(uint8_t * str, void *data, int *datalen);

#endif /*!P_LIBAWSCLIENT_H_*/
