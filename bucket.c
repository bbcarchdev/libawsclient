/* Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
 *
 * Copyright (c) 2014-2017 BBC
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stddef.h>
#include "p_libawsclient.h"

#if (defined(HAVE_VSYSLOG) || _BSD_SOURCE)
# define VSYSLOG_AVAILABLE
#endif

static int strdup_or_free_(void * const mem, void (* free_f)(void *), const size_t offset, const char * const nullable str, const char * const field);
static void aws_s3_bucket_free_(void * const nullable bucket);


/* Create an object representing an S3 bucket */
aws_mutable_s3_bucket_t
aws_s3_create_uri(URI *uri)
{
	aws_mutable_s3_bucket_t bucket;
	URI_INFO *info;
	const char *t;
	intmax_t n;

	info = uri_info(uri);
	if(!info) {
		fprintf(stderr, PACKAGE "::aws_s3_create_uri(): failed to extract information from URI\n");
		return NULL;
	}
	if(info->scheme && info->scheme[0] && strcasecmp(info->scheme, "s3")) {
		fprintf(stderr, PACKAGE "::aws_s3_create_uri(): URI provided does not use the \"s3\" scheme (<s3://...>)\n");
		uri_info_destroy(info);
		return NULL;
	}
	if(!info->host) {
		fprintf(stderr, PACKAGE "::aws_s3_create_uri(): no bucket name provided in S3 URI\n");
		uri_info_destroy(info);
		return NULL;
	}
	bucket = aws_s3_create(info->host);
	if(!bucket) {
		uri_info_destroy(info);
		return NULL;
	}
	if(info->user) {
		aws_s3_set_access(bucket, info->user);
	}
	if(info->pass) {
		aws_s3_set_secret(bucket, info->pass);
	}
	if(info->query) {
		if((t = uri_info_get(info, "endpoint", NULL))) {
			aws_s3_set_endpoint(bucket, t);
		}
		if((t = uri_info_get(info, "token", NULL))) {
			aws_s3_set_token(bucket, t);
		}
		if((t = uri_info_get(info, "access", NULL))) {
			aws_s3_set_access(bucket, t);
		}
		if((t = uri_info_get(info, "secret", NULL))) {
			aws_s3_set_secret(bucket, t);
		}
		if((t = uri_info_get(info, "region", NULL))) {
			aws_s3_set_region(bucket, t);
		}
		if((n = uri_info_get_int(info, "ver", 0))) {
			aws_s3_set_version(bucket, (int) n);
		}
	}
	uri_info_destroy(info);
	return bucket;
}

aws_mutable_s3_bucket_t
aws_s3_create_uristr(const char *uristr)
{
	URI *uri;
	AWSS3BUCKET *bucket;

	uri = uri_create_str(uristr, NULL);
	if(!uri) {
		fprintf(stderr, PACKAGE "::aws_s3_create_uristr(): failed to parse URI\n");
		return NULL;
	}
	bucket = aws_s3_create_uri(uri);
	uri_destroy(uri);
	return bucket;
}

aws_mutable_s3_bucket_t
aws_s3_create(const char *bucket)
{
	AWSS3BUCKET *p = (AWSS3BUCKET *) calloc(1, sizeof(AWSS3BUCKET));
	if(!p) return errno = ENOMEM, NULL;

	p->bucket = strdup(bucket);
	if(!p->bucket)
	{
		syslog(LOG_ERR, PACKAGE "::aws_s3_create(): failed to duplicate bucket name ('%s') while creating bucket instance\n", bucket);
		aws_s3_destroy(p);
		return errno = ENOMEM, NULL;
	}
#ifdef VSYSLOG_AVAILABLE
	p->logger = vsyslog;
#endif
	return p;
}

aws_s3_bucket_t
aws_s3_bucket_create_v1(
	aws_region_t nullable region,
	aws_s3_bucket_name_t nonnull name,
	aws_s3_bucket_endpoint_t nullable endpoint,
	aws_s3_bucket_basepath_t nullable basepath,
	aws_access_key_t nonnull access,
	aws_secret_key_t nonnull secret,
	aws_session_token_t nullable token,
	aws_signature_version_t sig_version,
	aws_logger_f logger
) {
	aws_mutable_s3_bucket_t b = aws_s3_create(name);
	if(!b) return NULL;

	size_t o_access = offsetof(struct aws_s3_bucket_struct, access);
	size_t o_secret = offsetof(struct aws_s3_bucket_struct, secret);
	size_t o_endpoint = offsetof(struct aws_s3_bucket_struct, endpoint);
	size_t o_basepath = offsetof(struct aws_s3_bucket_struct, basepath);
	size_t o_region = offsetof(struct aws_s3_bucket_struct, region);
	size_t o_token = offsetof(struct aws_s3_bucket_struct, token);

	void (*f)(void*) = aws_s3_bucket_free_;
	if(strdup_or_free_(b, f, o_access, access, "access key"))
		return NULL;
	if(strdup_or_free_(b, f, o_secret, secret, "secret key"))
		return NULL;
	if(strdup_or_free_(b, f, o_endpoint, endpoint, "endpoint override"))
		return NULL;
	if(strdup_or_free_(b, f, o_basepath, basepath, "basepath"))
		return NULL;
	if(strdup_or_free_(b, f, o_region, region, "aws region"))
		return NULL;
	if(strdup_or_free_(b, f, o_token, token, "session token"))
		return NULL;

	b->ver = sig_version;

#ifdef VSYSLOG_AVAILABLE
	b->logger = logger ?: vsyslog;
#else
	b->logger = logger;
#endif

	return b;
}

static int
strdup_or_free_(
	void * const mem,
	void (* free_f)(void *),
	const size_t offset,
	const char * const nullable str,
	const char * const field
) {
	if(str) {
		char ** const ptr = mem + offset;
		*ptr = strdup(str);
		if(*ptr == NULL) {
			syslog(LOG_ERR, PACKAGE ": failed to duplicate %s ('%s')\n", field, str);
			(void) free_f(mem);
			return errno = ENOMEM, -1;
		}
	}
	return 0;
}

/**
 * clone a bucket
 */
aws_s3_bucket_t
aws_s3_bucket_copy(aws_s3_bucket_t const nullable src)
{
	if(!src) return errno = EINVAL, NULL;

	return aws_s3_bucket_create_v1(
		src->region,
		src->bucket,
		src->endpoint,
		src->basepath,
		src->access,
		src->secret,
		src->token,
		src->ver,
		src->logger
	);
}

static void
aws_s3_bucket_free_(void * const nullable bucket)
{
	if(bucket) {
		(void) aws_s3_destroy((aws_mutable_s3_bucket_t) bucket);
	}
}


/* Free the resources used by a bucket */
int
aws_s3_destroy(aws_mutable_s3_bucket_t nonnull bucket)
{
	if(!bucket) return errno = EINVAL, -1;

	free((void *) bucket->bucket);
	free((void *) bucket->access);
	free((void *) bucket->secret);
	free((void *) bucket->endpoint);
	free((void *) bucket->basepath);
	free((void *) bucket->region);
	free((void *) bucket->token);
	free(bucket);
	return 0;
}

/* Set the name of the S3 bucket */
int
aws_s3_set_bucket_name(aws_mutable_s3_bucket_t const bucket, aws_s3_bucket_name_t const nonnull name)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(name);
	if(!p) return errno = ENOMEM, -1;

	void *old = (void *) bucket->bucket;
	bucket->bucket = p;
	free(old);
	return 0;
}

/* Obtain the name of the S3 bucket */
aws_s3_bucket_name_t
aws_s3_bucket_name(aws_s3_bucket_t bucket)
{
	return bucket->bucket;
}

/* Set the access key to be used in requests for this bucket */
int
aws_s3_set_access(aws_mutable_s3_bucket_t bucket, aws_access_key_t nonnull key)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(key);
	if(!p) return errno = ENOMEM, -1;

	void *old = (void *) bucket->access;
	bucket->access = p;
	free(old);
	return 0;
}

/* Set the secret to be used in requests for this bucket */
int
aws_s3_set_secret(aws_mutable_s3_bucket_t bucket, aws_secret_key_t nonnull key)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(key);
	if(!p) return errno = ENOMEM, -1;

	void *old = (void *) bucket->secret;
	bucket->secret = p;
	free(old);
	return 0;
}

/* Set the session token to be used in requests for this bucket */
int
aws_s3_set_token(aws_mutable_s3_bucket_t bucket, aws_session_token_t nonnull token)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(token);
	if(!p) return errno = ENOMEM, -1;

	void *old = (void *) bucket->token;
	bucket->ver = bucket->ver ?: AWS_SIGN_VERSION_4;
	bucket->token = p;
	free(old);
	return 0;
}

/* Set the endpoint to be used (in place of s3.amazonaws.com) */
int
aws_s3_set_endpoint(aws_mutable_s3_bucket_t bucket, aws_s3_bucket_endpoint_t nonnull host)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(host);
	if(!p) return errno = ENOMEM, -1;

	void *old = (void *) bucket->endpoint;
	bucket->endpoint = p;
	free(old);
	return 0;
}

const char *
aws_s3_endpoint(aws_s3_bucket_t bucket)
{
	return bucket->endpoint;
}

/* Set the region to be used (e.g., eu-west-1) */
int
aws_s3_set_region(aws_mutable_s3_bucket_t bucket, aws_region_t nonnull region)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(region);
	if(!p) return errno = ENOMEM, -1;

	void *old = (void *) bucket->region;
	bucket->ver = bucket->ver ?: AWS_SIGN_VERSION_4;
	bucket->region = p;
	free(old);
	return 0;
}

aws_region_t
aws_s3_region(aws_s3_bucket_t bucket)
{
	return bucket->region;
}


/* Set the base path to be used in future requests */
int
aws_s3_set_basepath(aws_mutable_s3_bucket_t bucket, aws_s3_bucket_basepath_t nonnull path)
{
	if(!bucket) return errno = EINVAL, -1;

	char *p = strdup(path);
	if(!p) return errno = ENOMEM, -1;

	free((void *) bucket->basepath);
	bucket->basepath = p;
	return 0;
}

aws_s3_bucket_basepath_t
aws_s3_basepath(aws_s3_bucket_t bucket)
{
	return bucket->basepath;
}

/* Set the authentication version used in future requests */
int
aws_s3_set_version(aws_mutable_s3_bucket_t nonnull restrict bucket, const aws_signature_version_t ver)
{
	if(!bucket) return errno = EINVAL, -1;

	bucket->ver = ver;
	return 0;
}

aws_signature_version_t
aws_s3_version(aws_s3_bucket_t nonnull restrict bucket)
{
	return bucket->ver;
}

/* Set the logging function */
int
aws_s3_set_logger(aws_mutable_s3_bucket_t bucket, void (*logger)())
{
	if(!bucket) return errno = EINVAL, -1;

#ifdef VSYSLOG_AVAILABLE
	bucket->logger = logger ?: vsyslog;
#else
	if(!logger) return errno = EINVAL, -1;
	bucket->logger = logger;
#endif
	return 0;
}

void
aws_s3_logf_(aws_mutable_s3_bucket_t bucket, int prio, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	bucket->logger(prio, format, ap);
}
