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

#ifndef LIBAWSCLIENT_H_
# define LIBAWSCLIENT_H_               1

# include <stdarg.h>
# include <curl/curl.h>
# include "attributes.h"

# ifndef LIBURI_H_
typedef struct uri_struct URI;
# endif

typedef const struct curl_slist * aws_header_list_t;
typedef mutable struct curl_slist * aws_mutable_header_list_t;

typedef const struct aws_s3_bucket_struct * aws_s3_bucket_t;
typedef mutable struct aws_s3_bucket_struct * aws_mutable_s3_bucket_t;

typedef const struct aws_request_struct * aws_request_t;
typedef mutable struct aws_request_struct * aws_mutable_request_t;

typedef const struct aws_signature_params_struct * aws_signature_params_t;

typedef const char * aws_region_t;
typedef const char * aws_s3_bucket_name_t;
typedef const char * aws_s3_bucket_endpoint_t;
typedef const char * aws_s3_bucket_basepath_t;
typedef const char * aws_s3_resource_key_t;
typedef const char * aws_request_method_t;
typedef const char * aws_access_key_t;
typedef const char * aws_secret_key_t;
typedef const char * aws_session_token_t;
typedef void (*aws_logger_f)(int priority, const char *format, va_list ap);

typedef enum
{
	AWS_SIGN_VERSION_DEFAULT = 0,
	AWS_SIGN_VERSION_2 = 2,
	AWS_SIGN_VERSION_4 = 4
} aws_signature_version_t;

/* Create an object representing an S3 bucket */
aws_s3_bucket_t aws_s3_bucket_create_v1(
	aws_region_t nullable region,
	aws_s3_bucket_name_t nonnull name,
	aws_s3_bucket_endpoint_t nullable endpoint,
	aws_s3_bucket_basepath_t nullable basepath,
	aws_access_key_t nonnull access,
	aws_secret_key_t nonnull secret,
	aws_session_token_t nullable token,
	aws_signature_version_t sig_version,
	aws_logger_f logger
) MALLOC;

aws_mutable_s3_bucket_t aws_s3_create(aws_s3_bucket_name_t bucket) MALLOC;
aws_mutable_s3_bucket_t aws_s3_create_uri(URI *uri) MALLOC;
aws_mutable_s3_bucket_t aws_s3_create_uristr(const char *uristr) MALLOC;

/* Free the resources used by a bucket */
int aws_s3_destroy(aws_mutable_s3_bucket_t nonnull bucket);

/* Set the logging function to use for this bucket */
int aws_s3_set_logger(aws_mutable_s3_bucket_t bucket, void (*logger)(int prio, const char *format, va_list ap));

/* Set the name of the S3 bucket */
int aws_s3_set_bucket_name(aws_mutable_s3_bucket_t bucket, aws_s3_bucket_name_t nonnull name);
aws_s3_bucket_name_t aws_s3_bucket_name(aws_s3_bucket_t bucket);
#define aws_s3_set_bucket(bucket, name)  	aws_s3_set_bucket_name(bucket, name)
#define aws_s3_bucket(bucket)   			aws_s3_bucket_name(bucket)

/* Set the access key to be used in requests for this bucket */
int aws_s3_set_access(aws_mutable_s3_bucket_t bucket, aws_access_key_t nonnull key);

/* Set the secret to be used in requests for this bucket */
int aws_s3_set_secret(aws_mutable_s3_bucket_t bucket, aws_secret_key_t nonnull key);

/* Set the session token to be used in requests for this bucket */
int aws_s3_set_token(aws_mutable_s3_bucket_t bucket, aws_session_token_t nonnull token);

/* Set the endpoint to be used (in place of s3.amazonaws.com) */
int aws_s3_set_endpoint(aws_mutable_s3_bucket_t bucket, aws_s3_bucket_endpoint_t nonnull host);
aws_s3_bucket_endpoint_t aws_s3_endpoint(aws_s3_bucket_t bucket);

/* Set the base path to be used for all requests to this bucket */
int aws_s3_set_basepath(aws_mutable_s3_bucket_t bucket, aws_s3_bucket_basepath_t nonnull path);
aws_s3_bucket_basepath_t aws_s3_basepath(aws_s3_bucket_t bucket);

/* Set the region (e.g., eu-west-2) to be used for all requests to this bucket */
int aws_s3_set_region(aws_mutable_s3_bucket_t bucket, aws_region_t nonnull region);
aws_region_t aws_s3_region(aws_s3_bucket_t bucket);

/* Set the authentication version */
int aws_s3_set_version(aws_mutable_s3_bucket_t nonnull restrict bucket, aws_signature_version_t version);
aws_signature_version_t aws_s3_version(aws_s3_bucket_t nonnull restrict bucket) PURE;

/* Create a new request for a resource within a bucket */
aws_mutable_request_t aws_s3_request_create(aws_mutable_s3_bucket_t nonnull bucket, aws_s3_resource_key_t nonnull resource, aws_request_method_t nonnull method);

/* Destroy a request */
int aws_request_destroy(aws_mutable_request_t request);

/* Finalise (sign) a request */
int aws_request_finalise(aws_mutable_request_t request);

/* Perform a request, finalising if needed */
int aws_request_perform(aws_mutable_request_t request);

/* Obtain (creating if needed) the cURL handle for this request */
CURL *aws_request_curl(aws_mutable_request_t request);

/* Set the headers list for this request (the list will be freed upon
 * request destruction).
 */
int aws_request_set_headers(aws_mutable_request_t request, aws_mutable_header_list_t headers);
aws_mutable_header_list_t aws_request_headers(aws_request_t request);

/* DEPRECATED
 * Sign an AWS S3 request, appending a suitable 'Authorization' header
 * to the list provided and returning the modified list of headers.
 */
typedef struct aws_s3_bucket_struct AWSS3BUCKET;
typedef struct aws_request_struct AWSREQUEST;
aws_header_list_t aws_s3_sign_default(aws_mutable_request_t nonnull request, aws_s3_resource_key_t resource) MALLOC;
aws_header_list_t aws_s3_sign(aws_request_method_t method, aws_s3_resource_key_t resource, aws_access_key_t access_key, aws_secret_key_t secret, aws_mutable_header_list_t nullable headers) MALLOC;

#endif /*!LIBAWSCLIENT_H_*/
