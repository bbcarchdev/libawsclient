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

typedef struct aws_s3_bucket_struct AWSS3BUCKET;
typedef struct aws_request_struct AWSREQUEST;
typedef struct aws_signature_params_struct AWSSIGN;

typedef enum
{
	AWS_SIGN_VERSION_DEFAULT = 0,
	AWS_SIGN_VERSION_2 = 2,
	AWS_SIGN_VERSION_4 = 4
} aws_signature_version;

struct aws_signature_params_struct
{
	aws_signature_version version;
	size_t size;
	time_t timestamp;
	char *method; /* not copied by curl_easy_setopt < 7.17.0 */
	char *resource; /* s3 resource key; non-s3 signing not yet supported */
	char *access_key;
	char *secret_key;
	char *token;
	char *region;
	char *host; /* can be derived from region if absent */
	char *service; /* used to build the v4 signature string */
	char *payloadhash;
};

/*** S3 INTERACTION WRAPPER ***/

/* Create an object representing a bucket and associated S3 service */
AWSS3BUCKET *aws_s3_create(const char *bucket_name) MALLOC;
AWSS3BUCKET *aws_s3_create_uri(URI *uri) MALLOC;
AWSS3BUCKET *aws_s3_create_uristr(const char *uristr) MALLOC;

/* Free the resources used by a service descriptor */
int aws_s3_destroy(AWSS3BUCKET *s3);

/* Set the logging function to use for this descriptor */
int aws_s3_set_logger(AWSS3BUCKET *s3, void (*logger)(int priority, const char *format, va_list ap));

/* Set the name of the S3 bucket */
int aws_s3_set_bucket_name(AWSS3BUCKET *s3, const char *name);
char *aws_s3_bucket_name(AWSS3BUCKET *s3);
#define aws_s3_set_bucket(descriptor, name)  	aws_s3_set_bucket_name(descriptor, name)
#define aws_s3_bucket(descriptor)   			aws_s3_bucket_name(descriptor)

/* Set the access key to be used in requests to this service */
int aws_s3_set_access(AWSS3BUCKET *s3, const char *key);

/* Set the secret to be used in requests to this service */
int aws_s3_set_secret(AWSS3BUCKET *s3, const char *key);

/* Set the session token to be used in requests to this service */
int aws_s3_set_token(AWSS3BUCKET *s3, const char *token);

/* Set the endpoint to be used (in place of s3.amazonaws.com) */
int aws_s3_set_endpoint(AWSS3BUCKET *s3, const char *host);
char *aws_s3_endpoint(AWSS3BUCKET *s3);

/* Set the base path to be used for all requests to this service */
int aws_s3_set_basepath(AWSS3BUCKET *s3, const char *path);
char *aws_s3_basepath(AWSS3BUCKET *s3);

/* Set the region (e.g., eu-west-2) to be used for all requests to this service */
int aws_s3_set_region(AWSS3BUCKET *s3, const char *region);
char *aws_s3_region(AWSS3BUCKET *s3);

/* Set the authentication version */
int aws_s3_set_version(AWSS3BUCKET *s3, aws_signature_version version);
aws_signature_version aws_s3_version(AWSS3BUCKET *s3) PURE;


/*** AWS REQUEST WRAPPERS FOR SUPPORTED SERVICES ***/

/* Create a new request for a resource provided by this service */
AWSREQUEST *aws_s3_request_create(AWSS3BUCKET *s3, const char *resource, const char *method);

/* Destroy a request */
int aws_request_destroy(AWSREQUEST *request);

/* Finalise (including signing) a request */
int aws_request_finalise(AWSREQUEST *request);

/* Perform a request, finalising if needed */
int aws_request_perform(AWSREQUEST *request);

/* Obtain (creating if needed) the cURL handle for this request */
CURL *aws_request_curl(AWSREQUEST *request);

/* Set the headers list for this request (the list will be freed upon
 * request destruction).
 */
int aws_request_set_headers(AWSREQUEST *request, struct curl_slist *headers);
struct curl_slist *aws_request_headers(AWSREQUEST *request);


/*** GENERIC SIGNATURE GENERATION ***/

/**
 * Sign a header list intended to be used for making an AWS request to the
 * service specified in the signature parameters object, appending a suitable
 * 'Authorization' header to the list provided and returning a new list of
 * headers. The input list is unmodified.
 */
struct curl_slist *aws_sign(const AWSSIGN *signature_params, struct curl_slist *headers);

/**
 * AWS optionally allows a payload hash to be provided with a signature. If,
 * for additional security, you would like to utilise this feature, store the
 * result of this function in the signature parameters before calling aws_sign.
 */
char *aws_sign_payload_hash(size_t payload_length, const uint8_t *payload);

/**
 * DEPRECATED
 * Sign (using v2) a header list intended to be used for making an S3 request,
 * appending a suitable 'Authorization' header to the list provided and
 * returning the now-modified list of headers (which may have a new head).
 */
struct curl_slist *aws_s3_sign(const char *method, const char *resource, const char *access_key, const char *secret, struct curl_slist *headers);

#endif /*!LIBAWSCLIENT_H_*/
