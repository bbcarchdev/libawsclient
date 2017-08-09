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

# ifdef WITH_COMMONCRYPTO
#  include <CommonCrypto/CommonCrypto.h>
# else
#  include <openssl/hmac.h>
#  include <openssl/evp.h>
#  include <openssl/bio.h>
#  include <openssl/buffer.h>
#  include <openssl/sha.h>
# endif

#include "p_libawsclient.h"
#include "aws_string.h"
#include "curl_slist.h"
#include "http.h"
#include "mem.h"

#ifndef SHA1_DIGEST_LENGTH
# define SHA1_DIGEST_LENGTH         20
#endif
#ifndef SHA256_DIGEST_LENGTH
# define SHA256_DIGEST_LENGTH       32
#endif

#define AUTHORIZATION "Authorization"
#define AWS_HMAC_SHA256 "AWS4-HMAC-SHA256"
#define AWS4_REQUEST "aws4_request"
#define CREDENTIAL "Credential"
#define EMPTY_STRING_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define EQ "="
#define HTTP_DATE_FORMAT_STR "%a, %d %b %Y %H:%M:%S GMT"
#define LONG_DATE_FORMAT_STR "%Y%m%dT%H%M%SZ"
#define NEWLINE "\n"
#define SIGNATURE "Signature"
#define SIGNED_HEADERS "SignedHeaders"
#define SIGNING_KEY "AWS4"
#define SIMPLE_DATE_FORMAT_STR "%Y%m%d"
#define UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"
#define X_AMZ_ALGORITHM "X-Amz-Algorithm"
#define X_AMZ_CONTENT_SHA256 "X-Amz-Content-SHA256"
#define X_AMZ_CREDENTIAL "X-Amz-Credential"
#define X_AMZ_SIGNATURE "X-Amz-Signature"
#define X_AMZ_SIGNED_HEADERS "X-Amz-SignedHeaders"

#define HTTP_DATE_LENGTH 29

static aws_mutable_request_t aws_request_sign_(aws_mutable_request_t nonnull restrict request, aws_signature_params_t nonnull restrict sign);
static aws_mutable_request_t aws_request_sign_v2_(aws_mutable_request_t restrict request, aws_signature_params_t restrict sign);
static aws_mutable_request_t aws_request_sign_v4_(aws_mutable_request_t restrict request, aws_signature_params_t restrict sign);
static aws_header_list_t aws_s3_request_signed_headers_v4_(aws_mutable_request_t nonnull req, const char *resource) MALLOC;
static aws_header_list_t aws_request_signed_headers_(aws_mutable_request_t nonnull restrict request, aws_signature_params_t nonnull restrict sign) MALLOC;
static aws_header_list_t aws_ensure_reqd_headers_are_present_(aws_request_t restrict request, aws_signature_params_t restrict sign) MALLOC;
static aws_header_list_t aws_create_reqd_headers_(aws_request_t restrict request, aws_signature_params_t restrict sign) MALLOC;
static aws_header_list_t aws_create_auth_headers_(aws_signature_params_t restrict sign, aws_header_list_t headers) MALLOC;
static const char *aws_create_amz_content_hash_header_(const char *value) MALLOC;
static const char *aws_create_authentication_v4_header_(aws_signature_params_t restrict sign, aws_header_list_t headers) MALLOC;
static const char *aws_header_credentials_(aws_signature_params_t restrict sign) MALLOC;
static const char *aws_credential_scope_(aws_signature_params_t restrict sign) MALLOC;
static const char *aws_signed_header_names_(aws_header_list_t restrict headers) MALLOC;
static const char *aws_signature_v4_(aws_signature_params_t restrict sign, aws_header_list_t restrict headers) MALLOC;
static const uint8_t *aws_signature_v4_digest_(aws_signature_params_t restrict sign, aws_header_list_t restrict headers) MALLOC;
static const uint8_t *aws_derived_signing_key_(aws_signature_params_t restrict sign) MALLOC;
static const char *aws_string_to_sign_(aws_signature_params_t restrict sign, aws_header_list_t restrict headers) MALLOC;
static const char *aws_canonical_request_description_hex_(aws_signature_params_t restrict sign, aws_header_list_t restrict headers) MALLOC;
static const char *aws_canonical_request_description_(aws_signature_params_t restrict sign, aws_header_list_t restrict headers) MALLOC;
static const char *aws_canonical_uri_(aws_signature_params_t restrict sign) MALLOC;
static const char *aws_normalised_path_(const char * restrict path) MALLOC;
static const char *aws_normalised_resource_key_(const char * restrict resource_key) MALLOC;
static const char *aws_canonical_query_string_(aws_signature_params_t restrict sign) MALLOC;
static const char *aws_canonical_headers_description_(aws_header_list_t restrict headers) MALLOC;
static const char *aws_canonical_header_(const char * nonnull restrict h) MALLOC;
static const char *aws_canonical_header_name_(const char * nonnull restrict h) MALLOC;
static const char *aws_canonical_header_value_(const char * nonnull restrict h) MALLOC;
static const char *aws_hex_(const uint8_t * nonnull bytes, size_t length) MALLOC;
static char aws_unhex_char_(char high, char low);
static const uint8_t *aws_sha256_(const char * nonnull restrict str) MALLOC;
static const uint8_t *aws_hmac_sha256_(size_t secret_key_length, const uint8_t * nonnull restrict secret_key, const char * nonnull restrict str) MALLOC;
static const char *aws_create_host_header_(aws_request_t nonnull request) MALLOC;
static int aws_header_sort_(const void * nonnull a, const void * nonnull b) PURE;
static int aws_bad_signing_data_(aws_signature_params_t const nonnull restrict sign);
static int aws_should_use_v2_sig_(aws_signature_params_t const nonnull restrict sign);

/**
 * returns the passed-in aws_request_t object with its headers (and potentially payload) signed
 */
static aws_mutable_request_t
aws_request_sign_(
	aws_mutable_request_t const nonnull restrict request,
	aws_signature_params_t const nonnull restrict sign
) {
	struct aws_signature_params_struct data = {};

	if(aws_bad_signing_data_(sign))
		return errno = EINVAL, NULL;
	memcpy(&data, sign, sign->size);
	data.size = sizeof (struct aws_signature_params_struct);

	// if(sign_payload) data.payloadhash = hex(sha256(request->payload), SHA256_DIGEST_LENGTH); else
	data.payloadhash = 0; // TODO: until we support signing payloads, set hash to zero
	if(!data.method) {
		data.method = "GET";
	}
	if(!data.resource) {
		data.resource = "/";
	}
	if(!data.access_key) {
		data.access_key = "";
	}
	if(!data.secret_key) {
		data.secret_key = "";
	}
	if(!data.timestamp) {
		data.timestamp = time(NULL);
	}

	if(aws_should_use_v2_sig_(&data)) {
		return aws_request_sign_v2_(request, &data);
	} else {
		return aws_request_sign_v4_(request, &data);
	}
}

static int
aws_bad_signing_data_(
	aws_signature_params_t const nonnull restrict sign
) {
	return (sign->size == 0) ||
		(sign->size > sizeof (struct aws_signature_params_struct)) ||
		(!sign->service);
}

static int
aws_should_use_v2_sig_(
	aws_signature_params_t const nonnull restrict sign
) {
	return sign->alg == AWS_ALG_SHA1 ||
		(sign->alg == AWS_ALG_DEFAULT &&
	  		!sign->token &&
	  		!sign->region &&
	  		!sign->payloadhash);
}

aws_header_list_t
aws_s3_sign_default(
	aws_mutable_request_t const nonnull request,
	aws_s3_resource_key_t const nonnull resource
) {
	if (!request || !request->bucket)
		return errno = EINVAL, NULL;

	switch (aws_s3_version(request->bucket)) {
		case AWS_SIGN_VERSION_4:
			return aws_s3_request_signed_headers_v4_(request, resource);
		case AWS_SIGN_VERSION_2:
		case AWS_SIGN_VERSION_DEFAULT:
			return aws_s3_sign(request->method, resource, request->bucket->access, request->bucket->secret, aws_request_headers(request));
		default: /* unknown version specified */
			return NULL;
	}
}

/* Legacy method for compatibility - always signs a request as S3, with SHA1 Auth */
aws_header_list_t
aws_s3_sign(
	aws_request_method_t const restrict method,
	aws_s3_resource_key_t const restrict resource,
	aws_access_key_t const restrict access_key,
	aws_secret_key_t const restrict secret,
	aws_mutable_header_list_t const nullable restrict headers
) {
	struct aws_signature_params_struct sign = {};
	struct aws_request_struct request = {};
	struct aws_s3_bucket_struct bucket = {};

	sign.alg = AWS_ALG_SHA1;
	sign.size = sizeof(struct aws_signature_params_struct);
	sign.service = "s3";
	sign.method = method;
	sign.resource = resource;
	sign.access_key = access_key;
	sign.secret_key = secret;

	request.bucket = &bucket;
	request.method = (char *) method;
	request.resource = (char *) resource;
	request.headers = headers;

	return aws_request_signed_headers_(&request, &sign);
}

static aws_header_list_t
aws_s3_request_signed_headers_v4_(
	aws_mutable_request_t const nonnull request,
	const char * const resource
) {
	struct aws_signature_params_struct sign = {};

	sign.alg = AWS_ALG_HMAC_SHA256;
	sign.size = sizeof(struct aws_signature_params_struct);
	sign.service = "s3";
	sign.method = request->method;
	sign.region = request->bucket->region;
	sign.resource = resource;
	sign.access_key = request->bucket->access;
	sign.secret_key = request->bucket->secret;
	sign.token = request->bucket->token;

	return aws_request_signed_headers_(request, &sign);
}

static aws_header_list_t
aws_request_signed_headers_(
	aws_mutable_request_t const nonnull restrict request,
	aws_signature_params_t const nonnull restrict sign
) {
	if (!request) return errno = EINVAL, NULL;
	(void) aws_request_sign_(request, sign);
	return aws_curl_slist_copy(aws_request_headers(request));
}

/* Sign request headers using the legacy SHA1-based scheme
 * http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
 */
static aws_mutable_request_t
aws_request_sign_v2_(
	aws_mutable_request_t const nullable restrict request,
	aws_signature_params_t restrict sign
) {
	const char *type, *md5, *date, *adate, *hp;
	size_t len, amzlen, amzcount, c, l;
	char *t, *s, *buf, *amzbuf;
	char **amzhdr;
	struct curl_slist *p;
	unsigned char digest[SHA1_DIGEST_LENGTH];
	unsigned digestlen;
	char *sigbuf;
	struct tm tm;
	char datebuf[64];
	aws_mutable_header_list_t hs = aws_request_headers(request);

	type = md5 = date = adate = NULL;
	len = strlen(sign->method) + strlen(sign->resource) + 2;
	amzcount = 0;
	amzlen = 0;
	for(p = hs; p; p = p->next)
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
	if(adate)
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
		/* TODO: why is this 57? HTTP_DATE_LENGTH == 29 */
		strftime(&(datebuf[6]), 57, HTTP_DATE_FORMAT_STR, &tm);
		hs = curl_slist_append(hs, datebuf);
		date = &(datebuf[6]);
	}
	len += amzlen + strlen(type) + strlen(md5) + strlen(date) + 2;
	buf = (char *) calloc(1, len + 16);
	if(!buf)
	{
		return NULL;
	}
	t = aws_stradd(buf, sign->method);
	*t++ = '\n';
	t = aws_stradd(t, md5);
	*t++ = '\n';
	t = aws_stradd(t, type);
	*t++ = '\n';
	t = aws_stradd(t, date);
	*t++ = '\n';
	if(amzcount)
	{
		/* Build an array of x-amz-* headers, excluding x-amz-date */
		amzhdr = (char **) calloc(amzcount, sizeof(char *));
		amzbuf = (char *) calloc(1, amzlen + 16);
		s = amzbuf;
		amzcount = 0;
		for(p = hs; p; p = p->next)
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
						*s++ = ':';
						hp++;
						while(isspace(*hp))
						{
							hp++;
						}
						strcpy(s, hp);
						s = strchr(s, 0);
						break;
					}
					*s++ = tolower(*hp);
					*s = '\0';
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
			t = aws_stradd(t, amzhdr[c]);
			while(c + 1 < amzcount && !strncmp(amzhdr[c + 1], amzhdr[c], l))
			{
				c++;
				*t++ = ',';
				t = aws_stradd(t, amzhdr[c] + l + 1);
			}
			*t++ = '\n';
		}
		free(amzbuf);
		free(amzhdr);
	}
	t = aws_stradd(t, sign->resource);

#ifdef WITH_COMMONCRYPTO
	CCHmac(kCCHmacAlgSHA1, sign->secret_key, strlen(sign->secret_key), buf, strlen(buf), digest);
	digestlen = CC_SHA1_DIGEST_LENGTH;
#else
	HMAC(EVP_sha1(), sign->secret_key, strlen(sign->secret_key), (unsigned char *) buf, strlen(buf), digest, &digestlen);
#endif
	free(buf);

	sigbuf = (char *) calloc(1, strlen(sign->access_key) + (digestlen * 2) + 20 + 16);
	t = aws_stradd(sigbuf, AUTHORIZATION ": AWS ");
	t = aws_stradd(t, sign->access_key);
	*t++ = ':';
	aws_base64_encode_(digest, digestlen, (uint8_t *) t);
	hs = curl_slist_append(hs, sigbuf);
	free(sigbuf);
	(void) aws_request_set_headers(request, hs);
	return request;
}

/**
 * sign request using the AWS4-HMAC-SHA256 scheme.
 * http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */
static aws_mutable_request_t
aws_request_sign_v4_(
	aws_mutable_request_t const nonnull restrict request,
	aws_signature_params_t const nonnull restrict sign
) {
	// TODO: implement payload signing
	// if(request->sign_payload)
	//    sign->payloadhash = compute_payload_hash(request);

	aws_mutable_header_list_t const headers_to_sign = (aws_mutable_header_list_t) aws_ensure_reqd_headers_are_present_(request, sign);
	aws_mutable_header_list_t auth_headers = (aws_mutable_header_list_t) aws_create_auth_headers_(sign, headers_to_sign);
	(void) aws_request_set_headers(request, (aws_mutable_header_list_t) aws_curl_slist_fold_left(
		(aws_mutable_header_list_t(*)(aws_mutable_header_list_t, const char *)) aws_set_http_header, // modifies 'headers_to_sign' and returns a pointer to a potentially new list head
		headers_to_sign,
		auth_headers
	));
	(void) aws_curl_slist_free(&auth_headers);
	return request;
}

/**
 * creates a new header list with required headers added
 * dispose of with aws_curl_slist_free()
 */
static aws_header_list_t
aws_ensure_reqd_headers_are_present_(
	aws_request_t const nonnull restrict request,
	aws_signature_params_t const nonnull restrict sign
) {
	aws_mutable_header_list_t const restrict hs = (aws_mutable_header_list_t) aws_curl_slist_copy(aws_request_headers(request)); // NULL is OK
	aws_mutable_header_list_t restrict reqd_headers = (aws_mutable_header_list_t) aws_create_reqd_headers_(request, sign);
	aws_header_list_t restrict headers_to_sign = aws_curl_slist_fold_left(
		(aws_mutable_header_list_t(*)(aws_mutable_header_list_t, const char *)) aws_set_http_header, // modifies 'hs' and returns a pointer to a potentially new list head
		hs,
		reqd_headers
	);
	(void) aws_curl_slist_free(&reqd_headers);
	return headers_to_sign;
}

static aws_header_list_t
aws_create_reqd_headers_(
	aws_request_t const nullable restrict request,
	aws_signature_params_t const nonnull restrict sign
) {
	char * restrict date_h = (char *) aws_create_http_date_header(&(sign->timestamp));
	if(!date_h) return NULL;

	char * restrict host_h = (char *) aws_create_host_header_(request);
	if(!host_h) {
		(void) aws_safe_free((void **) &date_h);
		return NULL;
	}

	const char * const list[] = {
		date_h,
		host_h,
		NULL
	};
	return aws_curl_slist_create_nocopy(list);
}

static aws_header_list_t
aws_create_auth_headers_(
	aws_signature_params_t const restrict sign,
	aws_header_list_t const restrict headers
) {
	char * restrict hash_h = (char *) aws_create_amz_content_hash_header_(sign->payloadhash ?: UNSIGNED_PAYLOAD);
	if(!hash_h) return NULL;

	char * restrict auth_h = (char *) aws_create_authentication_v4_header_(sign, headers);
	if(!auth_h) {
		(void) aws_safe_free((void **) &hash_h);
		return NULL;
	}

	const char * const list[] = {
		hash_h,
		auth_h,
		NULL
	};

	return aws_curl_slist_create_nocopy(list);
}

static const char *
aws_create_amz_content_hash_header_(const char * const restrict value)
{
	return aws_strf(X_AMZ_CONTENT_SHA256 ": %s", value);
}

static const char *
aws_create_authentication_v4_header_(
	aws_signature_params_t restrict sign,
	aws_header_list_t restrict headers
) {
	/*
	 * AccessKey = e.g. "AKIAIOSFODNN7EXAMPLE"
	 * SecretKey = e.g. "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	 * Region = e.g. "eu-west-1"
	 * Service = e.g. "s3"
     * RequestMethod = e.g. "PUT"
	 * RequestPayload = e.g. "JFIF..."
	 *
	 * SignatureV4Marker = "AWS4"
	 * SignatureV4Terminator = "aws4_request"
	 *
	 * Date = YYYYMMDD
	 * HashedDate = HMAC(SignatureV4Marker SecretKey, Date)
	 * HashedRegion = HMAC(HashedDate, Region)
	 * HashedService = HMAC(HashedRegion, Service)
	 * DerivedSigningKey = HMAC(HashedService, SignatureV4Terminator)
	 *
	 * Algorithm = "AWS4-HMAC-SHA256"
	 * DateTime = Date "T" HHMMSS "Z"
	 * CredentialScope = Date "/" Region "/" Service "/" SignatureV4Terminator
	 * UnsignedPayload = "UNSIGNED-PAYLOAD"
	 *
	 * HeaderCredentials = AccessKey "/" CredentialScope
     * CanonicalURI =
     *  "The canonical URI is the URI-encoded version of the absolute path component of the URI, which is everything in the URI from the HTTP host to the question mark character"
     * CanonicalQueryString =
     * CanonicalHeaders = (sorted list of all headers as (HeaderName ":" HeaderValue) strings ending with "\n")
	 * SignedHeaderNames = (sorted list of all lowercase header names delimited by ";")
	 *
	 * CanonicalRequestDescription =
     *  RequestMethod "\n"
     *  CanonicalURI "\n"
     *  CanonicalQueryString "\n"
     *  CanonicalHeaders "\n"
     *  SignedHeaderNames "\n"
     *  (Hex(SHA256(RequestPayload)) || UnsignedPayload)
	 *
	 * StringToSign =
	 *  Algorithm "\n"
	 *  DateTime "\n"
	 *  CredentialScope "\n"
	 *  Hex(SHA256(CanonicalRequestDescription))
	 *
	 * Signature = Hex(SHA256(DerivedSigningKey, StringToSign))
	 *
	 * AuthorizationHeader =
	 *  Algorithm
	 *  " Credential=" HeaderCredentials
	 *  ", SignedHeaders=" SignedHeaderNames
	 *  ", Signature=" Signature
	 */

	char * restrict creds = (char *) aws_header_credentials_(sign);
	if(!creds) return NULL;

	char * restrict names = (char *) aws_signed_header_names_(headers);
	if(!names) {
		(void) aws_safe_free((void **) &creds);
		return NULL;
	}

	char * restrict sig = (char *) aws_signature_v4_(sign, headers);
	if(!sig) {
		(void) aws_safe_free((void **) &names);
		(void) aws_safe_free((void **) &creds);
		return NULL;
	}

	const char * const restrict header = aws_strf(
		AUTHORIZATION ": "
			AWS_HMAC_SHA256
			" Credential=%s,"
			" SignedHeaders=%s,"
			" Signature=%s",
		creds,
		names,
		sig
	);
	(void) aws_safe_free((void **) &sig);
	(void) aws_safe_free((void **) &names);
	(void) aws_safe_free((void **) &creds);
	return header;
}

static const char *
aws_header_credentials_(aws_signature_params_t restrict sign)
{
	char * restrict scope = (char *) aws_credential_scope_(sign);
	if(!scope) return NULL;

	char * const substrings[] = {
		(char *) sign->access_key,
		scope,
		NULL
	};
	const char * const restrict credentials = aws_join_char('/', (const char **) substrings);
	(void) aws_safe_free((void **) &scope);
	return credentials;
}

static const char *
aws_credential_scope_(aws_signature_params_t restrict sign)
{
	char * restrict date = (char *) aws_timef(SIMPLE_DATE_FORMAT_STR, &(sign->timestamp));
	if(!date) return NULL;

	char * const substrings[] = {
		date,
		(char *) sign->region,
		(char *) sign->service,
		AWS4_REQUEST,
		NULL
	};
	const char * const restrict scope = aws_join_char('/', (const char **) substrings);
	(void) aws_safe_free((void **) &date);
	return scope;
}

/**
 * allocates and returns a string containing the lower-case names of each of
 * the passed-in list of HTTP headers.
 * pass in only the list of headers which should be signed.
 * returns NULL on failure.
 */
static const char *
aws_signed_header_names_(aws_header_list_t restrict headers)
{
	// TODO: this gets called twice with identical arguments. memoize?
	struct curl_slist * restrict names = (struct curl_slist *) aws_curl_slist_map_data(aws_http_header_name, headers);
	if(!names) return NULL;

	struct curl_slist * restrict sorted_names = (struct curl_slist *) aws_curl_slist_sort(strcasecmp, names);
	if(!sorted_names) {
		(void) aws_curl_slist_free(&names);
		return NULL;
	}

	char * restrict all_names = (char *) aws_curl_slist_join_char(';', sorted_names);
	if(!all_names) {
		(void) aws_curl_slist_free(&sorted_names);
		(void) aws_curl_slist_free(&names);
		return NULL;
	}

	const char * restrict all_names_lc = aws_strtolower(all_names);
	(void) aws_safe_free((void **) &all_names);
	(void) aws_curl_slist_free(&sorted_names);
	(void) aws_curl_slist_free(&names);
	return all_names_lc;
}

static const char *
aws_signature_v4_(
	aws_signature_params_t restrict sign,
	aws_header_list_t restrict headers
) {
	uint8_t * const digest = (uint8_t *) aws_signature_v4_digest_(sign, headers);
	if(!digest) return NULL;

	const char * const digest_hex = aws_hex_(digest, SHA256_DIGEST_LENGTH);
	(void) aws_safe_free((void **) &digest);
	return digest_hex;
}

static const uint8_t *
aws_signature_v4_digest_(
	aws_signature_params_t restrict sign,
	aws_header_list_t restrict headers
) {
	char *s = (char *) aws_string_to_sign_(sign, headers);
	if(!s) return NULL;

	uint8_t *key = (uint8_t *) aws_derived_signing_key_(sign);
	if(!key) {
		(void) aws_safe_free((void **) &s);
		return NULL;
	}

	const uint8_t * const digest = aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key, s);
	(void) aws_safe_free((void **) &key);
	(void) aws_safe_free((void **) &s);
	return digest;
}

static const uint8_t *
aws_derived_signing_key_(aws_signature_params_t restrict sign)
{
	char * restrict date = (char *) aws_timef(SIMPLE_DATE_FORMAT_STR, &(sign->timestamp));
	if(!date) return NULL;

	char * restrict secret = (char *) aws_strf(SIGNING_KEY "%s", sign->secret_key);
	if(!secret) {
		(void) aws_safe_free((void **) &date);
		return NULL;
	}

	uint8_t * restrict key1 = (uint8_t *) aws_hmac_sha256_(strlen(secret), (uint8_t *) secret, date);
	(void) aws_safe_free((void **) &secret);
	(void) aws_safe_free((void **) &date);
	if(!key1) return NULL;

	uint8_t * restrict key2 = (uint8_t *) aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key1, sign->region);
	(void) aws_safe_free((void **) &key1);
	if(!key2) return NULL;

	uint8_t * restrict key3 = (uint8_t *) aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key2, sign->service);
	(void) aws_safe_free((void **) &key2);
	if(!key3) return NULL;

	const uint8_t * const restrict key4 = aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key3, AWS4_REQUEST);
	(void) aws_safe_free((void **) &key3);
	return key4;
}

static const char *
aws_string_to_sign_(
	aws_signature_params_t restrict sign,
	aws_header_list_t restrict headers
) {
	char *date = (char *) aws_http_date(&(sign->timestamp));
	if(!date) return NULL;

	char *scope = (char *) aws_credential_scope_(sign);
	if(!scope) {
		(void) aws_safe_free((void **) &date);
		return NULL;
	}

	char *request_desc_hex = (char *) aws_canonical_request_description_hex_(sign, headers);
	if(!request_desc_hex) {
		(void) aws_safe_free((void **) &scope);
		(void) aws_safe_free((void **) &date);
		return NULL;
	}

	char *substrings[] = {
		AWS_HMAC_SHA256,
	    date,
	    scope,
	    request_desc_hex,
	    NULL
	};
	const char * const s = aws_join_char('\n', (const char **) substrings);
	(void) aws_safe_free((void **) &request_desc_hex);
	(void) aws_safe_free((void **) &scope);
	(void) aws_safe_free((void **) &date);
	return s;
}

static const char *
aws_canonical_request_description_hex_(
	aws_signature_params_t restrict sign,
	aws_header_list_t restrict headers
) {
	char *request_desc = (char *) aws_canonical_request_description_(sign, headers);
	if(!request_desc) return NULL;

	uint8_t *request_desc_hash = (uint8_t *) aws_sha256_(request_desc);
	(void) aws_safe_free((void **) &request_desc);
	if(!request_desc_hash) return NULL;

	char *request_desc_hex = (char *) aws_hex_(request_desc_hash, SHA256_DIGEST_LENGTH);
	(void) aws_safe_free((void **) &request_desc_hash);

	return request_desc_hex;
}

static const char *
aws_canonical_request_description_(
	aws_signature_params_t restrict sign,
	aws_header_list_t restrict headers
) {
	char * restrict canonical_url = (char *) aws_canonical_uri_(sign);
	if(!canonical_url) return NULL;

	char * restrict canonical_query = (char *) aws_canonical_query_string_(sign);
	if(!canonical_query) {
		(void) aws_safe_free((void **) &canonical_url);
		return NULL;
	}

	char * restrict canonical_headers = (char *) aws_canonical_headers_description_(headers);
	if(!canonical_headers) {
		(void) aws_safe_free((void **) &canonical_query);
		(void) aws_safe_free((void **) &canonical_url);
		return NULL;
	}

	char * restrict signed_headers = (char *) aws_signed_header_names_(headers);
	if(!signed_headers) {
		(void) aws_safe_free((void **) &canonical_headers);
		(void) aws_safe_free((void **) &canonical_query);
		(void) aws_safe_free((void **) &canonical_url);
		return NULL;
	}

	char *substrings[] = {
		(char *) sign->method,
		canonical_url,
		canonical_query,
		// v4 only:
		canonical_headers,
		signed_headers,
		(char *) (sign->payloadhash ?: UNSIGNED_PAYLOAD),
		NULL
	};
	const char * const restrict s = aws_join_char('\n', (const char **) substrings);
	(void) aws_safe_free((void **) &signed_headers);
	(void) aws_safe_free((void **) &canonical_headers);
	(void) aws_safe_free((void **) &canonical_query);
	(void) aws_safe_free((void **) &canonical_url);
	return s;
}

/**
 * what AWS calls a "canonical URI" is really just the
 * normalised path component of the URI, except for S3
 */
static const char *
aws_canonical_uri_(aws_signature_params_t restrict sign)
{
	if(!sign->resource || strcmp(sign->resource, "") == 0) {
		return strdup("/");
	}

	if(strcmp(sign->service, "s3") == 0) {
		return aws_normalised_resource_key_(sign->resource);
	}

	return aws_normalised_path_(sign->resource);
}

static const char *
aws_normalised_path_(const char * const restrict path)
{
    return uri_stralloc(uri_create_str(path, NULL));
}

static const char *
aws_normalised_resource_key_(const char * const restrict resource_key)
{
	char *decoded_key = malloc(strlen(resource_key) + 1);
	if (!decoded_key) return errno = ENOMEM, NULL;
	char *src = (char *) resource_key, *dst = decoded_key;
	while (*src) {
		if (*src == '%') {
			*dst++ = aws_unhex_char_(*(src + 1), *(src + 2));
			src += 3;
		} else *dst++ = *src++;
	}
	*dst = '\0';
	return decoded_key;
}

static const char *
aws_canonical_query_string_(aws_signature_params_t restrict sign)
{
	/* TODO : not implemented */
	(void) sign;
	return strdup("");
}

/**
 * returns a newly allocated string, or NULL on failure
 * header list can be NULL (which will result in an empty description)
 */
static const char *
aws_canonical_headers_description_(aws_header_list_t restrict headers)
{
	if(!headers) return strdup("");

	struct curl_slist * restrict sorted_headers = (struct curl_slist *) aws_curl_slist_sort(strcasecmp, headers);
	if(!sorted_headers) return NULL;

	struct curl_slist * restrict canonical_headers = (struct curl_slist *) aws_curl_slist_map_data(aws_canonical_header_, sorted_headers);
	(void) aws_curl_slist_free(&sorted_headers);

	const char * const restrict description = aws_curl_slist_concat(canonical_headers);
	(void) aws_curl_slist_free(&canonical_headers);
	return description;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static const char *
aws_canonical_header_(const char * const restrict header)
{
	char * restrict name = (char *) aws_canonical_header_name_(header);
	if(!name) return NULL;

	char * restrict value = (char *) aws_canonical_header_value_(header);
	if(!value) {
		(void) aws_safe_free((void **) &name);
		return NULL;
	}

	const char * const restrict hdr_canonical = aws_strf("%s:%s\n", name, value);
	(void) aws_safe_free((void **) &value);
	(void) aws_safe_free((void **) &name);
	return hdr_canonical;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static const char *
aws_canonical_header_name_(const char * const restrict header)
{
	char * restrict name = (char *) aws_http_header_name(header);
	if(!name) return NULL;

	const char * const restrict name_canonical = aws_strtolower(name);
	(void) aws_safe_free((void **) &name);
	return name_canonical;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static const char *
aws_canonical_header_value_(const char * const restrict h)
{
	char * restrict val = (char *) aws_http_header_value(h);
	if(!val) return NULL;

	char * restrict val_trimmed = (char *) aws_trim(' ', val);
	(void) aws_safe_free((void **) &val);
	if(!val_trimmed) {
		return NULL;
	}

	const char * const restrict val_canonical = aws_collapse(' ', val_trimmed);
	(void) aws_safe_free((void **) &val_trimmed);
	return val_canonical;
}

/**
 * returns a newly allocated string containing the lower-case ASCII hexa-
 * decimal representation of the first <length> bytes of the input buffer.
 * returns NULL on failure.
 */
static const char *
aws_hex_(const uint8_t * const restrict bytes, const size_t length)
{
	if(!bytes) return NULL;

	char * const restrict buffer = malloc(2 * length + 1); /* length of zero is OK */
	if(!buffer) return errno = ENOMEM, NULL;

	const uint8_t *b = bytes;
    const char * const hex = "0123456789abcdef";
    char *nybble = buffer;
    size_t i;
    for(i = 0; i < length; i++)
    {
        *nybble++ = hex[(*b >> 4) & 0xF];
        *nybble++ = hex[(*b++) & 0xF];
    }
    *nybble = '\0';
    return buffer;
}

static char
aws_unhex_char_(const char high, const char low)
{
	char c = '\0';
	if (high >= '0' && high <= '9') {
		c += (high - '0') << 4;
	}
	if (high >= 'a' && high <= 'f') {
		c += (high - 'a' + 10) << 4;
	}
	if (high >= 'A' && high <= 'F') {
		c += (high - 'A' + 10) << 4;
	}
	if (low >= '0' && low <= '9') {
		c += low - '0';
	}
	if (low >= 'a' && low <= 'f') {
		c += low - 'a' + 10;
	}
	if (low >= 'A' && low <= 'F') {
		c += low - 'A' + 10;
	}
	return c;
}

/**
 * compute the SHA256 hash of the null-terminated input string.
 *
 * allocates and returns a pointer to an unterminated buffer of size
 * SHA256_DIGEST_LENGTH containing binary data.
 * dispose of by passing to free().
 */
static const uint8_t *
aws_sha256_(const char * const restrict str)
{
#ifdef WITH_COMMONCRYPTO
	uint8_t * const restrict digest = malloc(CC_SHA256_DIGEST_LENGTH);
	if (!digest) return errno = ENOMEM, NULL;
    return CC_SHA256(str, strlen(str), digest);
#else
	uint8_t * const restrict digest = malloc(SHA256_DIGEST_LENGTH);
	if (!digest) return errno = ENOMEM, NULL;
    return SHA256((const unsigned char *) str, strlen(str), digest);
#endif
}

/**
 * generate a message authentication code for the input string, based
 * on the provided secret key, using the SHA256 hashing algorithm.
 *
 * allocates and returns a pointer to an unterminated buffer of size
 * SHA256_DIGEST_LENGTH containing binary data.
 * dispose of by passing to free().
 */
static const uint8_t *
aws_hmac_sha256_(
	const size_t secret_key_length,
	const uint8_t * const nullable restrict secret_key,
	const char * const nullable restrict str
) {
	if (!secret_key || !str) return NULL;

#ifdef WITH_COMMONCRYPTO
	uint8_t * const restrict digest = malloc(CC_SHA256_DIGEST_LENGTH);
	if (!digest) return errno = ENOMEM, NULL;
	(void) CCHmac(kCCHmacAlgSHA256, secret_key, secret_key_length, str, strlen(str), digest);
	return digest;
#else
	unsigned int digestlen;
	uint8_t * const restrict digest = malloc(EVP_MAX_MD_SIZE); /* use SHA256_DIGEST_LENGTH and avoid realloc? */
	if (!digest) return errno = ENOMEM, NULL;
	HMAC(EVP_sha256(), secret_key, secret_key_length, (unsigned char *) str, strlen(str), digest, &digestlen);
	return realloc(digest, digestlen);
#endif
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static const char *
aws_create_host_header_(aws_request_t const nonnull request)
{
	if(!request) return errno = EINVAL, NULL;
	const char *endpoint = aws_s3_endpoint(request->bucket);
	if(!endpoint) return errno = EINVAL, NULL;
	return aws_strf("Host: %s", endpoint);
}

static int
aws_header_sort_(const void * const nonnull a, const void * const nonnull b)
{
	return strcmp(*(const char **) a, *(const char **) b);
}
