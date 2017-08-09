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

/* Create a new request for a resource within a bucket */
AWSREQUEST *
aws_s3_request_create(AWSS3BUCKET *bucket, const char *resource, const char *method)
{
	AWSREQUEST *p;

	p = (AWSREQUEST *) calloc(1, sizeof(AWSREQUEST));
	if(!p)
	{
		return NULL;
	}
	p->bucket = bucket;
	p->resource = strdup(resource);
	p->method = strdup(method);
	if(!p->resource || !p->method)
	{
		aws_request_destroy(p);
		return NULL;
	}
	return p;
}

/* Destroy a request */
int
aws_request_destroy(AWSREQUEST *req)
{
	if(!req)
	{
		errno = EINVAL;
		return -1;
	}
	free(req->resource);
	free(req->method);
	free(req->url);
	if(req->ch)
	{
		curl_easy_cleanup(req->ch);
	}
	if(req->headers)
	{
		curl_slist_free_all(req->headers);
	}
	free(req);
	return 0;
}

/* Finalise (sign) a request */
int
aws_request_finalise(AWSREQUEST *req)
{
	CURL *ch;
	struct curl_slist *headers;
	size_t l;
	char *resource, *url, *p;
	const char *t;
	int r, ver;

	if(req->finalised)
	{
		return 0;
	}
	r = 0;  
	if(!req->bucket->bucket)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: bucket name is missing from request\n");
		r = -1;
	}
	if(!req->bucket->access)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: bucket access key is missing from request\n");
		r = -1;
	}
	if(!req->bucket->secret)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: bucket secret key is missing from request\n");
		r = -1;
	}
	if(r)
	{
		errno = EINVAL;
		return -1;
	}
	ch = aws_request_curl(req);
	if(!ch)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: failed to create cURL handle\n");
		return -1;
	}
	/* The resource path is signed in the request, and takes the form:
	 * /{bucket}/[{basepath}]/{resource}
	 */
	l = 1 + strlen(req->bucket->bucket) + 1 + (req->bucket->basepath ? strlen(req->bucket->basepath) : 0) + 1 + strlen(req->resource) + 1;
	resource = (char *) calloc(1, l + 16);
	if(!resource)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: failed to allocate memory for request-uri\n");
		return -1;
	}
	p = resource;
	*p = '/';
	p++;
	strcpy(p, req->bucket->bucket);
	p += strlen(req->bucket->bucket);
	*p = '/';
	p++;
	t = NULL;
	if(req->bucket->basepath)
	{
		/* Skip leading slashes, as there's already a trailing slash */
		t = req->bucket->basepath;
		while(*t == '/')
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
		strcpy(p, t);
		p += strlen(t) - 1;
		/* If there isn't a trailing slash, add one */
		if(*p != '/')
		{
			p++;
			*p = '/';
		}
		p++;
	}
	t = req->resource;
	/* Skip leading slashes in the resource path */
	while(*t == '/')
	{
		t++;
	}
	strcpy(p, t);
	/* The URL is http://{endpoint}{resource}
	 * endpoint is just a hostname (or conceivably, hostname:port)
	 * resource, created above, always has a leading slash
	 */
	l += 7 + strlen(req->bucket->endpoint) + 1;
	url = (char *) calloc(1, l + 16);
	if(!url)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: failed to allocate memory for S3 URL\n");
		free(resource);
		return -1;
	}
	p = url;
	strcpy(p, "http://");
	p += 7;
	strcpy(p, req->bucket->endpoint);
	p += strlen(req->bucket->endpoint);
	strcpy(p, resource);
	free(req->url);
	req->url = url;
	ver = aws_s3_version(req->bucket);
	if(ver == 4)
	{
		headers = aws_s3_sign_v4_hmacsha256(req->method, resource, req->bucket->access, req->bucket->secret, req->bucket->token, req->bucket->region, "s3", aws_request_headers(req));	
	}
	else
	{
		headers = aws_s3_sign(req->method, resource, req->bucket->access, req->bucket->secret, aws_request_headers(req));
	}
	if(!headers)
	{
		aws_s3_logf_(req->bucket, LOG_ERR, "S3: failed to sign request headers\n");
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
aws_request_perform(AWSREQUEST *req)
{
	int e;

	if(!req->finalised)
	{
		if(aws_request_finalise(req))
		{
			return CURLE_FAILED_INIT;
		}
	}
	if((e = curl_easy_perform(req->ch)) != CURLE_OK)
	{
		return e;
	}
	return CURLE_OK;
}

/* Obtain (creating if needed) the cURL handle for this request */
CURL *
aws_request_curl(AWSREQUEST *request)
{
	if(!request->ch)
	{
		request->ch = curl_easy_init();
		if(!request->ch)
		{
			return NULL;
		}
	}
	return request->ch;
}

/* Obtain the headers list for this request */
struct curl_slist *
aws_request_headers(AWSREQUEST *request)
{
	return request->headers;
}

/* Set the headers list for this request (the list will be freed upon
 * request destruction).
 */
int
aws_request_set_headers(AWSREQUEST *request, struct curl_slist *headers)
{
	request->headers = headers;
	return 0;
}
