/* Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
 *
 * Copyright (c) 2014-2016 BBC
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

static int aws_s3_request_sign_and_update_curl_(AWSREQUEST * restrict request, char * restrict resource);
static int aws_s3_request_sign_(AWSREQUEST * restrict request, char * restrict resource);
static char *aws_s3_build_request_url_(AWSREQUEST *request);
static char *aws_host_from_endpoint_(const char *endpoint) MALLOC;

/* Create a new request for a resource within a bucket */
AWSREQUEST *
aws_s3_request_create(
	AWSS3BUCKET * const s3,
	const char * const resource,
	const char * const method
) {
	AWSREQUEST *request;
	if(!s3)
	{
		fprintf(stderr, PACKAGE "::%s: S3 service struct must not be null\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	if(!resource)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: resource must not be null\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	if(!method)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: method must not be null\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	request = calloc(1, sizeof(AWSREQUEST));
	if(!request)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to allocate memory for request\n", __FUNCTION__);
		return errno = ENOMEM, NULL;
	}
	request->bucket = s3;
	request->resource = strdup(resource);
	request->method = strdup(method);
	if(!request->resource || !request->method)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to duplicate either resource or method strings\n", __FUNCTION__);
		aws_request_destroy(request);
		return errno = ENOMEM, NULL;
	}
	return request;
}

/* Destroy a request */
int
aws_request_destroy(AWSREQUEST * const request)
{
	if(!request)
	{
		return errno = EINVAL, -1;
	}
	free(request->resource);
	free(request->method);
	free(request->url);
	if(request->ch)
	{
		curl_easy_cleanup(request->ch);
	}
	aws_curl_slist_free(&request->headers);
	free(request);
	return 0;
}

/**
 * Finalise (sign) a request
 * ONLY SUPPORTS S3 at the moment
 * Creates an actual HTTP URL from the AWS parameters, and signs the request
 */
int
aws_request_finalise(AWSREQUEST * const request)
{
	char *resource;
	if(!request)
	{
		return errno = EINVAL, -1;
	}
	if(request->finalised)
	{
		return 0;
	}
	if(!request->bucket)
	{
		return errno = EINVAL, -1;
	}
	resource = aws_s3_build_request_url_(request);
	if(aws_s3_request_sign_and_update_curl_(request, resource) != 0)
	{
		free(resource);
		return -1;
	}
	request->finalised = 1;
	free(resource);
	return 0;
}


static int
aws_s3_request_sign_and_update_curl_(
	AWSREQUEST * const restrict request,
	char * const restrict resource
) {
	AWSS3BUCKET * const s3 = request->bucket;
	CURL *ch = aws_request_curl(request);
	if(!ch)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to create cURL handle\n", __FUNCTION__);
		return -1;
	}
	if(aws_s3_request_sign_(request, resource) != 0)
	{
		return -1;
	}
	curl_easy_setopt(ch, CURLOPT_HTTPHEADER, aws_request_headers(request));
	curl_easy_setopt(ch, CURLOPT_URL, request->url);
	curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, request->method);
	return 0;
}

static int
aws_s3_request_sign_(
	AWSREQUEST * const restrict request,
	char * const restrict resource
) {
	AWSSIGN sign = {};
	AWSS3BUCKET * const s3 = request->bucket;
	struct curl_slist *headers;

	sign.version = s3->version;
	sign.size = sizeof(AWSSIGN);
	sign.service = "s3";
	sign.method = request->method;
	sign.region = s3->region;
	sign.resource = resource;
	sign.access_key = s3->access;
	sign.secret_key = s3->secret;
	sign.token = s3->token;
	if(!aws_sign_credentials_are_anonymous(&sign))
	{
		sign.host = aws_host_from_endpoint_(s3->endpoint);
		headers = aws_sign(&sign, aws_request_headers(request));
		free(sign.host);
		if(!headers)
		{
			aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to sign request\n", __FUNCTION__);
			return -1;
		}
		(void) aws_request_set_headers(request, headers);
	}
	return 0;
}

static char *
aws_host_from_endpoint_(const char * const endpoint)
{
	/* input endpoint == [user [":" pass] "@"] host [":" port]
	   output host == "domain.name" or "dot.ted.qu.ad" or "[v6::addr]" */
	size_t length;
	char *start, *end, *host;
	if(!endpoint)
	{
		return NULL;
	}
	start = strchr(endpoint, '@');
	start = start ? start : (char *) endpoint;
	if(start[0] == '[')
	{
		/* IPv6 */
		end = strchr(start, ']');
		if(!end)
		{
			/* host addr malformed */
			return errno = EINVAL, NULL;
		}
		end++;
	}
	else
	{
		/* IPv4 or DNS */
		end = strchr(start, ':');
		if(!end)
		{
			return strdup(start);
		}
	}
	length = (size_t) (end - start);
	host = malloc(length + 1);
	memcpy(host, start, length);
	host[length] = '\0';
	return host;
}

/**
 * builds the HTTP-scheme request URL, assigns it to request->url, and returns the path part
 */
static char *
aws_s3_build_request_url_(AWSREQUEST * const request)
{
	size_t l;
	char *resource, *url, *p, *t, *tmp;
	AWSS3BUCKET *s3 = request->bucket;
	if(!s3->bucket)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: bucket name is missing from request\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	if(!s3->access)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: bucket access key is missing from request\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	if(!s3->secret)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: bucket secret key is missing from request\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	/* The resource path is signed in the request, and takes the form:
	 * /{bucket}/[{basepath}/]{resource}
	 */
	l = 1 + strlen(s3->bucket) + 1 + (s3->basepath ? strlen(s3->basepath) : 0) + 1 + strlen(request->resource) + 1;
	resource = (char *) calloc(1, l + 16);
	if(!resource)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to allocate memory for request-uri\n", __FUNCTION__);
		return NULL;
	}
	p = resource;
	*p++ = '/';
	p = aws_stradd(p, s3->bucket);
	*p++ = '/';
	t = (char *) s3->basepath;
	if(t)
	{
		/* Skip one leading slash from basepath, as it has already been added */
		if(*t == '/')
		{
			t++;
		}
		if(!*t)
		{
			t = NULL;
		}
	}
	if(t)
	{
		/* There's a non-empty base path */
		p = aws_stradd(p, t);
		/* always add a slash between the basepath and the resource */
		*p++ = '/';
	}
	strcpy(p, request->resource);
	/* The URL is http://{endpoint}{resource}
	 * endpoint is just a hostname (or conceivably, hostname:port); and
	 * resource, created above, already has a leading slash
	 */
	if(aws_s3_ensure_endpoint_is_specified_(request->bucket) != 0)
	{
		free(resource);
		return NULL;
	}
	l += 7 + strlen(s3->endpoint) + 1; /* 7 == strlen("http://") */
	url = (char *) calloc(1, l + 16);
	if(!url)
	{
		aws_s3_logf_(s3, LOG_ERR, PACKAGE "::%s: failed to allocate memory for S3 URL\n", __FUNCTION__);
		free(resource);
		return errno = ENOMEM, NULL;
	}
	p = aws_stradd(url, "http://");
	p = aws_stradd(p, s3->endpoint);
	(void) strcpy(p, resource);
	tmp = (char *) request->url;
	request->url = url;
	if(tmp)
	{
		aws_s3_logf_(s3, LOG_WARNING, PACKAGE "::%s: request URL already exists, should be empty - attempting to free().\n", __FUNCTION__);
		free(tmp);
	}
	return resource;
}

/* Perform a request, finalising if needed */
int
aws_request_perform(AWSREQUEST * const request)
{
	if(!request->finalised && aws_request_finalise(request))
	{
		return CURLE_FAILED_INIT;
	}
	return curl_easy_perform(request->ch);
}

/* Obtain (creating if needed) the cURL handle for this request */
CURL *
aws_request_curl(AWSREQUEST * const request)
{
	if(!request->ch)
	{
		request->ch = curl_easy_init();
	}
	return request->ch;
}

/* Obtain the headers list for this request */
struct curl_slist *
aws_request_headers(AWSREQUEST * const request)
{
	return request->headers;
}

/* Set the headers list for this request (freeing any previous list; the new
 * list will be freed upon request destruction). Call this before finalising
 * the request.
 */
int
aws_request_set_headers(AWSREQUEST * const request, struct curl_slist * const headers)
{
	struct curl_slist *old;
	if(request->finalised)
	{
		aws_s3_logf_(request->bucket, LOG_ERR, PACKAGE "::%s: attempted to change headers after finalising request.\n", __FUNCTION__);
		return errno = EINVAL, -1;
	}
	old = request->headers;
	request->headers = headers;
	curl_slist_free_all(old);
	return 0;
}
