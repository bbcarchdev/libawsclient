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

#ifndef CC_SHA1_DIGEST_LENGTH
# define CC_SHA1_DIGEST_LENGTH         20
#endif

struct curl_slist *aws_sign_headers_sha1_(AWSSIGN *sign, struct curl_slist *headers);
struct curl_slist *aws_sign_headers_hmac_sha256_(AWSSIGN *sign, struct curl_slist *headers);
static int aws_header_sort_(const void *a, const void *b);
static char *stradd_(char *dest, const char *src);

struct curl_slist *
aws_sign_headers(AWSSIGN *sign, struct curl_slist *headers)
{
	AWSSIGN data;
	
	if((sign->size == 0) || (sign->size > sizeof(AWSSIGN)) || (!sign->service))
	{
		errno = EINVAL;
		return NULL;
	}
	memset(&data, 0, sizeof(AWSSIGN));
	memcpy(&data, sign, sign->size);
	if(!data.method)
	{
		data.method = "GET";
	}
	if(!data.resource)
	{
		data.resource = "/";
	}
	if(!data.access_key)
	{
		data.access_key = "";
	}
	if(!data.secret_key)
	{
		data.secret_key = "";
	}
	if(!data.timestamp)
	{
		data.timestamp = time(NULL);
	}
	switch(data.alg)
	{
	case AWS_ALG_DEFAULT:
		if(data.token || data.region || data.payloadhash)
		{
			return aws_sign_headers_hmac_sha256_(&data, headers);
		}
		return aws_sign_headers_sha1_(&data, headers);
	case AWS_ALG_SHA1:
		return aws_sign_headers_sha1_(&data, headers);
	case AWS_ALG_HMAC_SHA256:
		return aws_sign_headers_hmac_sha256_(&data, headers);
	}
}

/* Legacy method for compatibility - always signs an S3 request with AWSv2 */
struct curl_slist *
aws_s3_sign(const char *method, const char *resource, const char *access_key, const char *secret, struct curl_slist *headers)
{
	AWSSIGN sign;
	
	memset(&sign, 0, sizeof(AWSSIGN));
	sign.alg = AWS_ALG_SHA1;
	sign.size = sizeof(AWSSIGN);
	sign.service = "s3";
	sign.method = method;
	sign.resource = resource;
	sign.access_key = access_key;
	sign.secret_key = secret;
	return aws_sign_headers(&sign, headers);
}

/* Sign request headers using the legacy SHA1-based scheme
 * http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
 */
struct curl_slist *
aws_sign_headers_sha1_(AWSSIGN *sign, struct curl_slist *headers)
{
	const char *type, *md5, *date, *adate, *hp;
	size_t len, amzlen, amzcount, c, l;
	char *t, *s, *buf, *amzbuf;
	char **amzhdr;
	struct curl_slist *p;
	unsigned char digest[CC_SHA1_DIGEST_LENGTH];
	unsigned digestlen;
	char *sigbuf;
	time_t now;
	struct tm tm;
	char datebuf[64];

	type = md5 = date = adate = NULL;
	len = strlen(sign->method) + strlen(sign->resource) + 2;
	amzcount = 0;
	amzlen = 0;
	for(p = headers; p; p = p->next)
	{
		if(!strncasecmp(p->data, "content-type: ", 14))
		{
			type = p->data + 14;
		}
		else if(!strncasecmp(p->data, "content-md5: ", 13))
		{
			md5 = p->data + 13;
		}
		else if(!strncasecmp(p->data, "date: ", 6))
		{
			date = p->data + 6;
		}
		else if(!strncasecmp(p->data, "x-amz-date: ", 12))
		{
			adate = p->data + 12;
		}
		else if(!strncasecmp(p->data, "x-amz-", 6))
		{
			amzlen += strlen(p->data) + 1;
			amzcount++;
		}
	}
	else if(adate)
	{
		/* x-amz-date takes precedence over date */
		date = adate;
	}
	if(!type)
	{
		type = "";
	}
	if(!md5)
	{
		md5 = "";
	}
	if(!date)
	{
		/* If no date was specified, provide one */
		
		gmtime_r(&(sign->timestamp), &tm);
		strcpy(datebuf, "Date: ");
		strftime(&(datebuf[6]), 57, "%a, %d %b %Y %H:%M:%S GMT", &tm);		
		headers = curl_slist_append(headers, datebuf);
		date = &(datebuf[6]);
	}
	len += amzlen + strlen(type) + strlen(md5) + strlen(date) + 2;
	buf = (char *) calloc(1, len + 16);
	if(!buf)
	{
		return NULL;
	}
	t = stradd_(buf, sign->method);
	*t = '\n';
	t++;
	t = stradd_(t, md5);
	*t = '\n';
	t++;
	t = stradd_(t, type);
	*t = '\n';
	t++;
	t = stradd_(t, date);
	*t = '\n';
	t++;
	if(amzcount)
	{
		/* Build an array of x-amz-* headers, excluding x-amz-date */
		amzhdr = (char **) calloc(amzcount, sizeof(char *));
		amzbuf = (char *) calloc(1, amzlen + 16);
		s = amzbuf;
		amzcount = 0;
		for(p = headers; p; p = p->next)
		{
			if(!strncasecmp(p->data, "x-amz-date: ", 12))
			{
				continue;
			}
			else if(!strncasecmp(p->data, "x-amz-", 6))
			{
				amzhdr[amzcount] = s;
				amzcount++;
				for(hp = p->data; *hp; hp++)
				{
					if(*hp == ':')
					{
						*s = ':';
						s++;
						hp++;
						while(isspace(*hp))
						{
							hp++;
						}
						strcpy(s, hp);
						s = strchr(s, 0);
						break;
					}
					*s = tolower(*hp);
					s++;
					*s = 0;
				}
				s++;
			}
		}
		qsort(amzhdr, amzcount, sizeof(char *), aws_header_sort_);
		for(c = 0; c < amzcount; c++)
		{			
			hp = strchr(amzhdr[c], ':');
			if(!hp)
			{
				continue;
			}
			l = hp - amzhdr[c];
			t = stradd_(t, amzhdr[c]);
			while(c + 1 < amzcount && !strncmp(amzhdr[c + 1], amzhdr[c], l))
			{
				c++;
				*t = ',';
				t++;
				t = stradd_(t, amzhdr[c] + l + 1);
			}
			*t = '\n';
			t++;
		}
		free(amzbuf);
		free(amzhdr);
	}
	t = stradd_(t, sign->resource);
#ifdef WITH_COMMONCRYPTO
	CCHmac(kCCHmacAlgSHA1, sign->secret_key, strlen(sign->secret_key), buf, strlen(buf), digest);
	digestlen = CC_SHA1_DIGEST_LENGTH;
#else
	HMAC(EVP_sha1(), sign->secret_key, strlen(sign->secret_key), (unsigned char *) buf, strlen(buf), digest, &digestlen);
#endif
	free(buf);

	sigbuf = (char *) calloc(1, strlen(sign->access_key) + (digestlen * 2) + 20 + 16);
	t = stradd_(sigbuf, "Authorization: AWS ");
	t = stradd_(t, sign->access_key);
	*t = ':';
	t++;
	aws_base64_encode_(digest, digestlen, (uint8_t *) t);
	headers = curl_slist_append(headers, sigbuf);
	free(sigbuf);
	return headers;
}

/* Sign request headers using the AWS4 HMAC-SHA256 scheme
 * http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */

struct curl_slist *
aws_s3_sign_headers_hmac_sha256_(AWSSIGN *sign, struct curl_slist *headers)
{
	const char *uri, *query, *headerstr;
	char *creq;
	size_t urilen, querylen, headerstrlen, creqlen;
	
	/* First, create a canonical request and determine the request date
	 * CanonicalRequest =
     *  HTTPRequestMethod + '\n' +
     *  CanonicalURI + '\n' +
     *  CanonicalQueryString + '\n' +
     *  CanonicalHeaders + '\n' +
     *  SignedHeaders + '\n' +
     *  HexEncode(SHA256(RequestPayload))
	 */
	creq = NULL;
	creqlen = 0;
	uri = NULL;
	urilen = 0;
	
	creqlen += strlen(sign->method) + 1;
	
	
	query = NULL;
	querylen = 0;
	
	headerstr = NULL;
	headerstrlen = 0;
	
	/* Create a signing key:
	 *
	 * HMAC(HMAC(HMAC(HMAC("AWS4" + secret, "YYYYMMDD"), region), service),"aws4_request")
	 */
	
	/* Create the string to sign:
	 * StringToSign =
	 *  Algorithm ("AWS4-HMAC-SHA256") + '\n' +
	 *  RequestDatetime + '\n' +
	 *  CredentialScope + '\n' +
	 *  SHA256(CanonicalRequest)
	 */
	
	/* Finally, generate the signature:
	 * signature = HexEncode(HMAC(derived signing key, string to sign))
	 */
	return headers;
}

static int
aws_header_sort_(const void *a, const void *b)
{
	const char **stra, **strb;

	stra = (const char **) a;
	strb = (const char **) b;

	return strcmp(*stra, *strb);
}

static char *
stradd_(char *dest, const char *src)
{
	strcpy(dest, src);
	return strchr(dest, 0);
}
