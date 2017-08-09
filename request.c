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
#include "aws_string.h"
#include "curl_slist.h"

static int ensure_bucket_specifies_endpoint_(aws_mutable_request_t restrict req);
static const char *aws_s3_create_hostname(aws_request_t nullable restrict request) MALLOC;
static int has_valid_endpoint_(aws_request_t nullable restrict request) PURE;
static int has_valid_nondefault_region_(aws_request_t nullable restrict request) PURE;

/* Create a new request for a resource within a bucket */
aws_mutable_request_t
aws_s3_request_create(aws_mutable_s3_bucket_t const nonnull bucket, aws_s3_resource_key_t const nonnull resource, aws_request_method_t const nonnull method)
{
	if(!bucket) return errno = EINVAL, NULL;

	if(!resource)
	{
		aws_s3_logf_(bucket, LOG_ERR, PACKAGE "::aws_s3_request_create: resource must not be null\n");
		return errno = EINVAL, NULL;
	}

	if(!method)
	{
		aws_s3_logf_(bucket, LOG_ERR, PACKAGE "::aws_s3_request_create: method must not be null\n");
		return errno = EINVAL, NULL;
	}

	aws_mutable_request_t p = (aws_mutable_request_t) calloc(1, sizeof(struct aws_request_struct));
	if(!p)
	{
		aws_s3_logf_(bucket, LOG_ERR, PACKAGE ": failed to allocate memory for request\n");
		return errno = ENOMEM, NULL;
	}
	p->bucket = bucket;
	p->resource = strdup(resource);
	p->method = strdup(method);
	if(!p->resource || !p->method)
	{
		aws_s3_logf_(bucket, LOG_ERR, PACKAGE "::aws_s3_request_create: failed to duplicate resource or method strings\n");
		aws_request_destroy(p);
		return errno = ENOMEM, NULL;
	}
	return p;
}

/* Destroy a request */
int
aws_request_destroy(aws_mutable_request_t req)
{
	if(!req) return errno = EINVAL, -1;
	free((void *) req->resource);
	free((void *) req->method);
	free(req->url);
	if(req->ch)
	{
		curl_easy_cleanup(req->ch);
	}
	aws_curl_slist_free(&req->headers);
	free(req);
	return 0;
}

/* Finalise (sign) a request */
int
aws_request_finalise(aws_mutable_request_t req)
{
	CURL *ch;
	aws_mutable_header_list_t headers;
	size_t l;
	char *resource, *url, *p, *t, *tmp;

	if(req->finalised)
	{
		return 0;
	}
	if(!req->bucket->bucket)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": bucket name is missing from request\n");
		return errno = EINVAL, -1;
	}
	if(!req->bucket->access)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": bucket access key is missing from request\n");
		return errno = EINVAL, -1;
	}
	if(!req->bucket->secret)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": bucket secret key is missing from request\n");
		return errno = EINVAL, -1;
	}
	ch = aws_request_curl(req);
	if(!ch)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": failed to create cURL handle\n");
		return -1;
	}
	/* The resource path is signed in the request, and takes the form:
	 * /{bucket}/[{basepath}/]{resource}
	 */
	l = 1 + strlen(req->bucket->bucket) + 1 + (req->bucket->basepath ? strlen(req->bucket->basepath) : 0) + 1 + strlen(req->resource) + 1;
	resource = (char *) calloc(1, l + 16);
	if(!resource)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": failed to allocate memory for request-uri\n");
		return -1;
	}
	p = resource;
	*p++ = '/';
	p = aws_stradd(p, req->bucket->bucket);
	*p++ = '/';
	t = (char *) req->bucket->basepath;
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
	strcpy(p, req->resource);
	/* The URL is http://{endpoint}{resource}
	 * endpoint is just a hostname (or conceivably, hostname:port); and
	 * resource, created above, already has a leading slash
	 */
	if(ensure_bucket_specifies_endpoint_(req) != 0)
	{
		free(resource);
		return -1;
	}
	l += 7 + strlen(req->bucket->endpoint) + 1; // 7 == strlen("http://")
	url = (char *) calloc(1, l + 16);
	if(!url)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": failed to allocate memory for S3 URL\n");
		free(resource);
		return errno = ENOMEM, -1;
	}
	p = aws_stradd(url, "http://");
	p = aws_stradd(p, req->bucket->endpoint);
	(void) strcpy(p, resource);
	tmp = req->url;
	req->url = url;
	if(tmp)
	{
		aws_s3_logf_(req->bucket, LOG_WARNING, PACKAGE ": request URL already exists, should be empty - attempting to free().\n");
		free(tmp);
	}
	headers = (aws_mutable_header_list_t) aws_s3_sign_default(req, resource);
	if(!headers)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": failed to sign request\n");
		free(resource);
		return -1;
	}
	req->finalised = 1;
	req->headers = headers;
	curl_easy_setopt(ch, CURLOPT_HTTPHEADER, req->headers);
	curl_easy_setopt(ch, CURLOPT_URL, req->url);
	curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, req->method);
	free(resource);
	return 0;
}

/* Perform a request, finalising if needed */
int
aws_request_perform(aws_mutable_request_t req)
{
	if(!req->finalised && aws_request_finalise(req)) {
		return CURLE_FAILED_INIT;
	}

	return curl_easy_perform(req->ch);
}

/* Obtain (creating if needed) the cURL handle for this request */
CURL *
aws_request_curl(aws_mutable_request_t request)
{
	if(!request->ch) {
		request->ch = curl_easy_init();
	}

	return request->ch;
}

/* Obtain the headers list for this request */
aws_mutable_header_list_t
aws_request_headers(aws_request_t request)
{
	return request->headers;
}

/* Set the headers list for this request (the list will be freed upon
 * request destruction). Set this before finalising the request.
 */
int
aws_request_set_headers(aws_mutable_request_t request, aws_mutable_header_list_t headers)
{
	if(request->finalised) {
		aws_s3_logf_(request->bucket, LOG_ERR, PACKAGE ": attempted to change headers after finalising request.\n");
		return errno = EINVAL, -1;
	}

	request->headers = headers;
	return 0;
}

static int
ensure_bucket_specifies_endpoint_(aws_mutable_request_t req)
{
	char *endpoint;

	// already set
	if(req->bucket->endpoint) return 0;

	// generate from region if available, use default endpoint otherwise
	endpoint = (char *) aws_s3_create_hostname(req);
	if(!endpoint)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": failed to allocate memory for S3 endpoint\n");
		return errno = ENOMEM, -1;
	}

	// set the endpoint on the bucket
	if(aws_s3_set_endpoint(req->bucket, endpoint) != 0)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, PACKAGE ": could not set default endpoint for region %s\n", req->bucket->region);
		free(endpoint);
		return -1;
	}
	free(endpoint);
	return 0;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static const char *
aws_s3_create_hostname(aws_request_t const nullable restrict request)
{
	if(has_valid_endpoint_(request))
		return strdup(request->bucket->endpoint);
	else if(has_valid_nondefault_region_(request))
		return aws_strf(S3_REGIONAL_ENDPOINT_FORMAT, request->bucket->region);
	else return strdup(S3_DEFAULT_ENDPOINT);
}

static int
has_valid_endpoint_(aws_request_t const nullable restrict request)
{
	// TODO: only supports UTF-8 hostnames; does not validate string is actually a hostname + maybe port
	return request &&
		request->bucket &&
		request->bucket->endpoint &&
		strlen(request->bucket->endpoint) > 0;
}

static int
has_valid_nondefault_region_(aws_request_t const nullable restrict request)
{
	// TODO: does not validate the string pattern conforms to known AWS region names
	return request &&
		request->bucket &&
		request->bucket->region &&
		strlen(request->bucket->region) > 0 &&
		strcmp(AWS_DEFAULT_REGION, request->bucket->region) != 0;
}
