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

# ifndef LIBURI_H_
typedef struct uri_struct URI;
# endif

typedef struct aws_s3_bucket_struct AWSS3BUCKET;
typedef struct aws_request_struct AWSREQUEST;
typedef struct aws_sign_v1_struct AWSSIGN;

typedef enum
{
	AWS_ALG_DEFAULT = 0,
	AWS_ALG_SHA1 = 2,
	AWS_ALG_HMAC_SHA256 = 4
} AWSALG;

struct aws_sign_v1_struct
{
	AWSALG alg;
	size_t size;
	const char *method;
	const char *resource;
	const char *access_key;
	const char *secret_key;
	const char *token;
	const char *region;
	const char *service;
	time_t timestamp;
	const char *payloadhash;
};

/* Create an object representing an S3 bucket */
AWSS3BUCKET *aws_s3_create(const char *bucket);
AWSS3BUCKET *aws_s3_create_uri(URI *uri);
AWSS3BUCKET *aws_s3_create_uristr(const char *uristr);

/* Free the resources used by a bucket */
int aws_s3_destroy(AWSS3BUCKET *bucket);

/* Set the logging function to use for this bucket */
int aws_s3_set_logger(AWSS3BUCKET *bucket, void (*logger)(int prio, const char *format, va_list ap));

/* Set the name of the S3 bucket */
int aws_s3_set_bucket(AWSS3BUCKET *bucket, const char *name);

/* Obtain the name of the S3 bucket */
const char *aws_s3_bucket(AWSS3BUCKET *bucket);

/* Set the access key to be used in requests for this bucket */
int aws_s3_set_access(AWSS3BUCKET *bucket, const char *key);

/* Set the secret to be used in requests for this bucket */
int aws_s3_set_secret(AWSS3BUCKET *bucket, const char *key);

/* Set the session token to be used in requests for this bucket */
int aws_s3_set_token(AWSS3BUCKET *bucket, const char *token);

/* Set the endpoint to be used (in place of s3.amazonaws.com) */
int aws_s3_set_endpoint(AWSS3BUCKET *bucket, const char *host);
const char *aws_s3_endpoint(AWSS3BUCKET *bucket);

/* Set the base path to be used for all requests to this bucket */
int aws_s3_set_basepath(AWSS3BUCKET *bucket, const char *path);
const char *aws_s3_basepath(AWSS3BUCKET *bucket);

/* Set the region (e.g., eu-west-2) to be used for all requests to this bucket */
int aws_s3_set_region(AWSS3BUCKET *bucket, const char *region);
const char *aws_s3_region(AWSS3BUCKET *bucket);

/* Set the authentication version */
int aws_s3_set_version(AWSS3BUCKET *bucket, int version);
int aws_s3_version(AWSS3BUCKET *bucket);

/* Create a new request for a resource within a bucket */
AWSREQUEST *aws_s3_request_create(AWSS3BUCKET *bucket, const char *resource, const char *method);

/* Destroy a request */
int aws_request_destroy(AWSREQUEST *request);

/* Finalise (sign) a request */
int aws_request_finalise(AWSREQUEST *request);

/* Perform a request, finalising if needed */
int aws_request_perform(AWSREQUEST *request);

/* Obtain (creating if needed) the cURL handle for this request */
CURL *aws_request_curl(AWSREQUEST *request);

/* Obtain the headers list for this request */
struct curl_slist *aws_request_headers(AWSREQUEST *request);

/* Set the headers list for this request (the list will be freed upon
 * request destruction).
 */
int aws_request_set_headers(AWSREQUEST *request, struct curl_slist *headers);

/* Sign a set of request headers */
struct curl_slist *aws_sign_headers(AWSSIGN *sign, struct curl_slist *headers);

/* DEPRECATED Sign an AWS S3 request, appending a suitable 'Authorization: AWS ...' header
 * to the list provided.
 */
struct curl_slist *aws_s3_sign(const char *method, const char *resource, const char *access_key, const char *secret, struct curl_slist *headers);

#endif /*!LIBAWSCLIENT_H_*/
