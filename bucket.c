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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "p_libawsclient.h"

/* Create an object representing an S3 bucket */
AWSS3BUCKET *
aws_s3_create_uri(URI *uri)
{
	AWSS3BUCKET *bucket;
	URI_INFO *info;
	
	info = uri_info(uri);
	if(!info)
	{
		fprintf(stderr, "S3: failed to extract information from URI\n");
		return NULL;
	}
	if(info->scheme && info->scheme[0] && strcasecmp(info->scheme, "s3"))
	{
		fprintf(stderr, "S3: provided URI is not an S3 URI (<s3://...>)\n");
		uri_info_destroy(info);
		return NULL;
	}
	if(!info->host)
	{
		fprintf(stderr, "S3: no bucket name provided in S3 URI\n");
		uri_info_destroy(info);
		return NULL;
	}
	bucket = aws_s3_create(info->host);
	if(!bucket)
	{
		uri_info_destroy(info);
		return NULL;
	}
	if(info->user)
	{
		aws_s3_set_access(bucket, info->user);
	}
	if(info->pass)
	{
		aws_s3_set_secret(bucket, info->pass);	
	}
	if(info->query)
	{
		fprintf(stderr, "S3: query is '%s'\n", info->query);
	}
	uri_info_destroy(info);
	return bucket;
}

AWSS3BUCKET *
aws_s3_create_uristr(const char *uristr)
{
	URI *uri;
	AWSS3BUCKET *bucket;
	
	uri = uri_create_str(uristr, NULL);
	if(!uri)
	{
		fprintf(stderr, "S3: failed to parse URI\n");
		return NULL;
	}
	bucket = aws_s3_create_uri(uri);
	uri_destroy(uri);
	return bucket;
}

AWSS3BUCKET *
aws_s3_create(const char *bucket)
{
	AWSS3BUCKET *p;

	p = (AWSS3BUCKET *) calloc(1, sizeof(AWSS3BUCKET));
	if(!p)
	{
		return NULL;
	}
	p->bucket = strdup(bucket);
	p->endpoint = strdup(S3_DEFAULT_ENDPOINT);
	if(!p->bucket || !p->endpoint)
	{
		syslog(LOG_ERR, "S3: failed to duplicate bucket ('%s') or endpoint ('%s') strings while creating bucket instance\n", bucket, S3_DEFAULT_ENDPOINT);
		aws_s3_destroy(p);
		return NULL;
	}
	p->logger = vsyslog;
	return p;
}

/* Free the resources used by a bucket */
int
aws_s3_destroy(AWSS3BUCKET *bucket)
{
	if(!bucket)
	{
		errno = EINVAL;
		return -1;
	}
	free(bucket->bucket);
	free(bucket->access);
	free(bucket->secret);	
	free(bucket->endpoint);
	free(bucket->basepath);
	free(bucket);
	return 0;
}

/* Set the name of the S3 bucket */
int
aws_s3_set_bucket(AWSS3BUCKET *bucket, const char *name)
{
	char *p;

	p = strdup(name);
	if(!p)
	{
		return -1;
	}
	free(bucket->bucket);
	bucket->bucket = p;
	return 0;
}

/* Obtain the name of the S3 bucket */
const char *
aws_s3_bucket(AWSS3BUCKET *bucket)
{
	return bucket->bucket;
}

/* Set the access key to be used in requests for this bucket */
int
aws_s3_set_access(AWSS3BUCKET *bucket, const char *key)
{
	char *p;

	p = strdup(key);
	if(!p)
	{
		return -1;
	}
	free(bucket->access);
	bucket->access = p;
	return 0;
}

/* Set the secret to be used in requests for this bucket */
int
aws_s3_set_secret(AWSS3BUCKET *bucket, const char *key)
{
	char *p;

	p = strdup(key);
	if(!p)
	{
		return -1;
	}
	free(bucket->secret);
	bucket->secret = p;
	return 0;
}

/* Set the endpoint to be used (in place of s3.amazonaws.com) */
int
aws_s3_set_endpoint(AWSS3BUCKET *bucket, const char *host)
{
	char *p;

	p = strdup(host);
	if(!p)
	{
		return -1;
	}
	free(bucket->endpoint);
	bucket->endpoint = p;
	return 0;
}

/* Set the base path to be used in future requests */
int
aws_s3_set_basepath(AWSS3BUCKET *bucket, const char *path)
{
	char *p;

	p = strdup(path);
	if(!p)
	{
		return -1;
	}
	free(bucket->basepath);
	bucket->basepath = p;
	return 0;
}

/* Set the logging function */
int
aws_s3_set_logger(AWSS3BUCKET *bucket, void (*logger)())
{
	if(!logger)
	{
		bucket->logger = vsyslog;
	}
	else
	{
		bucket->logger = logger;
	}
	return 0;
}

void
aws_s3_logf_(AWSS3BUCKET *bucket, int prio, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	bucket->logger(prio, format, ap);
}