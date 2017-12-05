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

#include "p_libawsclient.h"

static char *aws_s3_create_endpoint_(const AWSS3BUCKET *s3) AWS_MALLOC;
static int aws_s3_has_valid_endpoint_(const AWSS3BUCKET *s3) AWS_PURE;
static int aws_s3_has_valid_nondefault_region_(const AWSS3BUCKET *s3) AWS_PURE;

/* Create an object representing an S3-compatible service */
AWSS3BUCKET *
aws_s3_create_uri(URI *uri)
{
	AWSS3BUCKET *s3;
	URI_INFO *info;
	const char *t;
	intmax_t n;
	info = uri_info(uri);
	if(!info)
	{
		fprintf(stderr, PACKAGE "::aws_s3_create_uri(): failed to extract information from URI\n");
		return NULL;
	}
	if(info->scheme && info->scheme[0] && strcasecmp(info->scheme, "s3"))
	{
		fprintf(stderr, PACKAGE "::aws_s3_create_uri(): URI provided does not use the \"s3\" scheme (<s3://...>)\n");
		uri_info_destroy(info);
		return errno = EINVAL, NULL;
	}
	if(!info->host)
	{
		fprintf(stderr, PACKAGE "::aws_s3_create_uri(): no bucket name provided in S3 URI\n");
		uri_info_destroy(info);
		return errno = EINVAL, NULL;
	}
	s3 = aws_s3_create(info->host);
	if(!s3)
	{
		uri_info_destroy(info);
		return NULL;
	}
	if(info->user)
	{
		aws_s3_set_access(s3, info->user);
	}
	if(info->pass)
	{
		aws_s3_set_secret(s3, info->pass);
	}
	if(info->query)
	{
		if((t = uri_info_get(info, "endpoint", NULL)))
		{
			aws_s3_set_endpoint(s3, t);
		}
		if((t = uri_info_get(info, "token", NULL)))
		{
			aws_s3_set_token(s3, t);
		}
		if((t = uri_info_get(info, "access", NULL)))
		{
			aws_s3_set_access(s3, t);
		}
		if((t = uri_info_get(info, "secret", NULL)))
		{
			aws_s3_set_secret(s3, t);
		}
		if((t = uri_info_get(info, "region", NULL)))
		{
			aws_s3_set_region(s3, t);
		}
		if((n = uri_info_get_int(info, "ver", 0)))
		{
			aws_s3_set_version(s3, (int) n);
		}
	}
	uri_info_destroy(info);
	return s3;
}

AWSS3BUCKET *
aws_s3_create_uristr(const char * const uristr)
{
	URI *uri;
	AWSS3BUCKET *s3;
	uri = uri_create_str(uristr, NULL);
	if(!uri)
	{
		fprintf(stderr, PACKAGE "::aws_s3_create_uristr(): failed to parse URI\n");
		return NULL;
	}
	s3 = aws_s3_create_uri(uri);
	uri_destroy(uri);
	return s3;
}

AWSS3BUCKET *
aws_s3_create(const char * const bucket)
{
	AWSS3BUCKET *s3;
	s3 = calloc(1, sizeof(AWSS3BUCKET));
	if(!s3)
	{
		return errno = ENOMEM, NULL;
	}
	s3->bucket = strdup(bucket);
	if(!s3->bucket)
	{
		syslog(LOG_ERR, PACKAGE "::aws_s3_create(): failed to duplicate bucket name ('%s') while creating bucket instance\n", bucket);
		aws_s3_destroy(s3);
		return errno = ENOMEM, NULL;
	}
#ifdef HAVE_VSYSLOG
	s3->logger = vsyslog;
#endif
	return s3;
}

/* Free the resources used by an S3 service descriptor */
int
aws_s3_destroy(AWSS3BUCKET * const s3)
{
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	free(s3->bucket);
	free(s3->access);
	free(s3->secret);
	free(s3->endpoint);
	free(s3->basepath);
	free(s3->region);
	free(s3->token);
	free(s3);
	return 0;
}

/* Set the name of the S3 bucket */
int
aws_s3_set_bucket(AWSS3BUCKET * const s3, const char * const name)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(name);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->bucket;
	s3->bucket = p;
	free(old);
	return 0;
}

/* Obtain the name of the S3 bucket */
char *
aws_s3_bucket_name(AWSS3BUCKET * const s3)
{
	if(!s3)
	{
		return NULL;
	}
	return s3->bucket;
}

/* Set the access key to be used in requests to this bucket */
int
aws_s3_set_access(AWSS3BUCKET * const s3, const char * const key)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(key);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->access;
	s3->access = p;
	free(old);
	return 0;
}

/* Set the secret to be used in requests to this bucket */
int
aws_s3_set_secret(AWSS3BUCKET * const s3, const char * const key)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(key);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->secret;
	s3->secret = p;
	free(old);
	return 0;
}

/* Set the session token to be used in requests to this bucket */
int
aws_s3_set_token(AWSS3BUCKET * const s3, const char * const token)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(token);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->token;
	s3->token = p;
	free(old);
	return 0;
}

/* Set the endpoint to be used (in place of s3.amazonaws.com) */
int
aws_s3_set_endpoint(AWSS3BUCKET * const s3, const char * const host)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(host);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->endpoint;
	s3->endpoint = p;
	free(old);
	return 0;
}

char *
aws_s3_endpoint(AWSS3BUCKET * const s3)
{
	if(!s3)
	{
		return NULL;
	}
	return s3->endpoint;
}

/* Set the region to be used (e.g., eu-west-1) */
int
aws_s3_set_region(AWSS3BUCKET * const s3, const char * const region)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(region);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->region;
	s3->region = p;
	free(old);
	return 0;
}

char *
aws_s3_region(AWSS3BUCKET * const s3)
{
	if(!s3)
	{
		return NULL;
	}
	return s3->region;
}

/* Set the base path to be used in future requests */
int
aws_s3_set_basepath(AWSS3BUCKET * const s3, const char * const path)
{
	char *p, *old;
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	p = strdup(path);
	if(!p)
	{
		return errno = ENOMEM, -1;
	}
	old = (char *) s3->basepath;
	s3->basepath = p;
	free(old);
	return 0;
}

char *
aws_s3_basepath(AWSS3BUCKET * const s3)
{
	if(!s3)
	{
		return NULL;
	}
	return s3->basepath;
}

/* Set the authentication version used in future requests */
int
aws_s3_set_version(AWSS3BUCKET * const s3, const aws_signature_version v)
{
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
	s3->version = v;
	return 0;
}

aws_signature_version
aws_s3_version(AWSS3BUCKET * const s3)
{
	if(!s3)
	{
		return AWS_SIGN_VERSION_DEFAULT;
	}
	return s3->version;
}

/* Set the logging function */
int
aws_s3_set_logger(AWSS3BUCKET * const s3, void (* const logger)())
{
	if(!s3)
	{
		return errno = EINVAL, -1;
	}
#ifdef HAVE_VSYSLOG
	s3->logger = logger ? logger : vsyslog;
#else
	if(!logger)
	{
		return errno = EINVAL, -1;
	}
	s3->logger = logger;
#endif
	return 0;
}

int
aws_s3_ensure_endpoint_is_specified_(AWSS3BUCKET * const s3)
{
	char *endpoint;
	if(aws_s3_has_valid_endpoint_(s3))
	{
		return 0;
	}
	/* generate from region if available, use default endpoint otherwise */
	endpoint = aws_s3_create_endpoint_(s3);
	if(!endpoint)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to build S3 endpoint\n", __FUNCTION__);
		return -1;
	}
	/* set the endpoint for the bucket */
	if(aws_s3_set_endpoint(s3, endpoint) != 0)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: could not set default endpoint for region %s\n", __FUNCTION__, s3->region);
		free(endpoint);
		return -1;
	}
	free(endpoint);
	return 0;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static char *
aws_s3_create_endpoint_(const AWSS3BUCKET * const s3)
{
	if(aws_s3_has_valid_nondefault_region_(s3))
	{
		/* if region == default, this format is not valid */
		return aws_strf(S3_REGIONAL_ENDPOINT_FORMAT, s3->region);
	}
	return strdup(S3_DEFAULT_ENDPOINT);
}

static int
aws_s3_has_valid_endpoint_(const AWSS3BUCKET * const s3)
{
	/* TODO: only supports UTF-8 hostnames; does not validate string is actually a hostname + maybe port */
	return s3 &&
		s3->endpoint &&
		strlen(s3->endpoint) > 0;
}

static int
aws_s3_has_valid_nondefault_region_(const AWSS3BUCKET * const s3)
{
	/* TODO: does not validate the string pattern conforms to known AWS region names */
	return s3 &&
		s3->region &&
		strlen(s3->region) > 0 &&
		strcmp(AWS_DEFAULT_REGION, s3->region) != 0;
}

void
aws_s3_logf_(AWSS3BUCKET * const s3, const int prio, const char * const format, ...)
{
	va_list ap;
	va_start(ap, format);
	s3->logger(prio, format, ap);
}
