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

static struct curl_slist *aws_sign_headers_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers);
static struct curl_slist *aws_sign_headers_v2_(const AWSSIGN * restrict sign, struct curl_slist *headers);
static struct curl_slist *aws_sign_headers_v4_(const AWSSIGN * restrict sign, struct curl_slist *headers);
static int aws_apply_signature_param_defaults_(AWSSIGN * const restrict dst, const AWSSIGN * const restrict src);
static struct curl_slist *aws_request_headers_including_reqd_(const AWSSIGN * restrict sign, struct curl_slist *headers) MALLOC;
static struct curl_slist *aws_create_reqd_headers_(const AWSSIGN * restrict sign) MALLOC;
static struct curl_slist *aws_create_auth_headers_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static char *aws_create_amz_content_hash_header_(char *value) MALLOC;
static char *aws_create_authentication_v4_header_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static char *aws_header_credentials_(const AWSSIGN *sign) MALLOC;
static char *aws_credential_scope_(const AWSSIGN *sign) MALLOC;
static char *aws_signed_header_names_(struct curl_slist *headers) MALLOC;
static char *aws_signature_v4_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static uint8_t *aws_signature_v4_digest_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static uint8_t *aws_derived_signing_key_(const AWSSIGN *sign) MALLOC;
static char *aws_string_to_sign_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static char *aws_canonical_request_description_hex_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static char *aws_canonical_request_description_(const AWSSIGN * restrict sign, struct curl_slist * restrict headers) MALLOC;
static char *aws_canonical_uri_(const AWSSIGN *sign) MALLOC;
static char *aws_normalised_path_(char *path) MALLOC;
static char *aws_normalised_resource_key_(char *resource_key) MALLOC;
static char *aws_canonical_query_string_(const AWSSIGN *sign) MALLOC;
static char *aws_canonical_headers_description_(struct curl_slist *headers) MALLOC;
static char *aws_canonical_header_(char *h) MALLOC;
static char *aws_canonical_header_name_(char *h) MALLOC;
static char *aws_canonical_header_value_(char *h) MALLOC;
static char *aws_hex_(size_t length, const uint8_t *bytes) MALLOC;
static uint8_t aws_unhex_byte_(char high, char low) CONST;
static uint8_t *aws_sha256_(const char *str) MALLOC;
static uint8_t *aws_sha256_binary_(size_t data_length, const uint8_t *data) MALLOC;
static uint8_t *aws_hmac_sha256_(size_t secret_key_length, const uint8_t * restrict secret_key, char * restrict str) MALLOC;
static char *aws_create_host_header_(const char *host) MALLOC;
static int aws_header_sort_(const void *a, const void *b) PURE;

static int aws_signing_params_are_bad_(const AWSSIGN * const sign);
static int aws_should_use_v2_sig_(const AWSSIGN * const sign);

char *
aws_sign_payload_hash(
	const size_t payload_length,
	const uint8_t * const payload
) {
	if(payload_length == 0)
	{
		/* for best performance in degenerate case */
		return strdup(EMPTY_STRING_SHA256);
	}
	if(!payload)
	{
		fprintf(stderr, "%s: payload missing\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	return aws_hex_(SHA256_DIGEST_LENGTH, aws_sha256_binary_(payload_length, payload));
}

struct curl_slist *
aws_sign(
	const AWSSIGN * const sign,
	struct curl_slist * const headers
) {
	struct curl_slist *in_headers, *out_headers;
	if(aws_signing_params_are_bad_(sign))
	{
		/* malformed signature params struct is an error */
		fprintf(stderr, "%s: signing params are bad\n", __FUNCTION__);
		return errno = EINVAL, NULL;
	}
	in_headers = aws_curl_slist_copy(headers);
	if(headers && !in_headers)
	{
		fprintf(stderr, "%s: failed to copy header list\n", __FUNCTION__);
		return errno = ENOMEM, NULL;
	}
	/* out_headers is in_headers, but potentially with a new head */
	out_headers = aws_sign_headers_(sign, in_headers);
	if(!out_headers)
	{
		aws_curl_slist_free(&in_headers);
		fprintf(stderr, "%s: failed to sign headers\n", __FUNCTION__);
		return NULL;
	}
	return out_headers;
}

static int
aws_signing_params_are_bad_(
	const AWSSIGN * const sign
) {
	return !sign
		|| (sign->size == 0)
		|| (sign->size > sizeof (AWSSIGN))
		|| (!sign->service);
}

/* Legacy method for compatibility - modifies input list and always uses v2 */
struct curl_slist *
aws_s3_sign(
	const char * const method,
	const char * const resource,
	const char * const access_key,
	const char * const secret_key,
	struct curl_slist * const headers
) {
	AWSSIGN sign = {};

	sign.version = AWS_SIGN_VERSION_2;
	sign.size = sizeof(AWSSIGN);
	sign.service = "s3";
	sign.method = (char *) method;
	sign.resource = (char *) resource;
	sign.access_key = (char *) access_key;
	sign.secret_key = (char *) secret_key;

	return aws_sign_headers_(&sign, headers);
}

static struct curl_slist *
aws_sign_headers_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	if(aws_sign_credentials_are_anonymous(sign))
	{
		/* anonymous requests cannot be signed, but not an error */
		return headers;
	}
	else
	{
		AWSSIGN data = {};
		(void) aws_apply_signature_param_defaults_(&data, sign);
		if(aws_should_use_v2_sig_(&data))
		{
			return aws_sign_headers_v2_(&data, headers);
		}
		else
		{
			return aws_sign_headers_v4_(&data, headers);
		}
	}
}

int
aws_sign_credentials_are_anonymous(const AWSSIGN * const sign)
{
	return aws_strempty(sign->access_key)
		|| aws_strempty(sign->secret_key);
}

static int
aws_apply_signature_param_defaults_(
	AWSSIGN * const restrict dst,
	const AWSSIGN * const restrict src
) {
	(void) memcpy(dst, src, src->size);
	dst->size = sizeof(AWSSIGN);
	if(!dst->method)
	{
		dst->method = "GET";
	}
	if(!dst->resource)
	{
		dst->resource = "/";
	}
	if(!dst->timestamp)
	{
		dst->timestamp = time(NULL);
	}
	return 0;
}

static int
aws_should_use_v2_sig_(
	const AWSSIGN * const sign
) {
	return sign->version == AWS_SIGN_VERSION_2
		|| (sign->version == AWS_SIGN_VERSION_DEFAULT &&
	  		!sign->token &&
	  		!sign->region &&
	  		!sign->payloadhash);
}

/* Sign request headers using the legacy SHA1-based scheme
 * http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
 */
static struct curl_slist *
aws_sign_headers_v2_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * restrict headers
) {
	char *type, *md5, *date, *adate, *hp;
	size_t len, amzlen, amzcount, c, l;
	char *t, *s, *buf, *amzbuf;
	char **amzhdr;
	struct curl_slist *p;
	unsigned char digest[SHA1_DIGEST_LENGTH];
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
		now = sign->timestamp ? sign->timestamp : time(NULL);
		gmtime_r(&now, &tm);
		strcpy(datebuf, "Date: ");
		/* TODO: why is this 57? HTTP_DATE_LENGTH == 29 */
		strftime(&(datebuf[6]), 57, HTTP_DATE_FORMAT_STR, &tm);
		headers = curl_slist_append(headers, datebuf);
		date = &(datebuf[6]);
	}
	len += amzlen + strlen(type) + strlen(md5) + strlen(date) + 2;
	buf = (char *) calloc(1, len + 16);
	if(!buf)
	{
		fprintf(stderr, "%s: failed to allocate buffer\n", __FUNCTION__);
		return errno = ENOMEM, NULL;
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
	headers = curl_slist_append(headers, sigbuf);
	free(sigbuf);
	if(!headers)
	{
		fprintf(stderr, "%s: failed to append buffer to header list\n", __FUNCTION__);
		return errno = ENOMEM, NULL;
	}
	return headers;
}

/**
 * sign request using the v4 signature procedure.
 * http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */
static struct curl_slist *
aws_sign_headers_v4_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	struct curl_slist * const headers_to_sign = aws_request_headers_including_reqd_(sign, headers);
	struct curl_slist *auth_headers = aws_create_auth_headers_(sign, headers_to_sign);
	struct curl_slist * const out = aws_curl_slist_fold_left(
		aws_set_http_header, /* modifies 'headers_to_sign' and returns a pointer to a potentially new list head */
		headers_to_sign,
		auth_headers
	);
	(void) aws_curl_slist_free(&auth_headers);
	return out;
}

/**
 * creates a new header list with required headers added
 * dispose of with aws_curl_slist_free()
 */
static struct curl_slist *
aws_request_headers_including_reqd_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	struct curl_slist * const request_headers = aws_curl_slist_copy(headers); /* NULL is OK */
	struct curl_slist *reqd_headers = aws_create_reqd_headers_(sign);
	struct curl_slist *all_headers = aws_curl_slist_fold_left(
		aws_set_http_header, /* modifies 'request_headers' and returns a pointer to a potentially new list head */
		request_headers,
		reqd_headers
	);
	(void) aws_curl_slist_free(&reqd_headers);
	return all_headers;
}

static struct curl_slist *
aws_create_reqd_headers_(const AWSSIGN * const sign)
{
	char *list[3];
	list[0] = aws_create_http_date_header(&(sign->timestamp));
	if(!list[0])
	{
		fprintf(stderr, "%s: failed to create Date header\n", __FUNCTION__);
		return NULL;
	}
	list[1] = aws_create_host_header_(sign->host);
	if(!list[1])
	{
		(void) free(list[0]);
		fprintf(stderr, "%s: failed to create Host header\n", __FUNCTION__);
		return NULL;
	}
	list[2] = NULL;
	return aws_curl_slist_create_nocopy(list);
}

static struct curl_slist *
aws_create_auth_headers_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	char *list[3];
	list[0] = aws_create_amz_content_hash_header_(sign->payloadhash ? sign->payloadhash : UNSIGNED_PAYLOAD);
	if(!list[0])
	{
		fprintf(stderr, "%s: failed to create v4 Amz-Content-Hash header\n", __FUNCTION__);
		return NULL;
	}
	list[1] = aws_create_authentication_v4_header_(sign, headers);
	if(!list[1])
	{
		(void) free(list[0]);
		fprintf(stderr, "%s: failed to create v4 Authentication header\n", __FUNCTION__);
		return NULL;
	}
	list[2] = NULL;
	return aws_curl_slist_create_nocopy(list);
}

static char *
aws_create_amz_content_hash_header_(char * const value)
{
	return aws_strf(X_AMZ_CONTENT_SHA256 ": %s", value);
}

static char *
aws_create_authentication_v4_header_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	/* AccessKey = e.g. "AKIAIOSFODNN7EXAMPLE"
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

	char *creds, *names, *sig, *header;
	creds = aws_header_credentials_(sign);
	if(!creds)
	{
		fprintf(stderr, "%s: failed to build v4 credentials string\n", __FUNCTION__);
		return NULL;
	}
	names = aws_signed_header_names_(headers);
	if(!names)
	{
		(void) free(creds);
		fprintf(stderr, "%s: failed to build v4 signed header names string\n", __FUNCTION__);
		return NULL;
	}
	sig = aws_signature_v4_(sign, headers);
	if(!sig)
	{
		(void) free(names);
		(void) free(creds);
		fprintf(stderr, "%s: failed to build v4 signature\n", __FUNCTION__);
		return NULL;
	}
	header = aws_strf(
		AUTHORIZATION ": "
			AWS_HMAC_SHA256
			" Credential=%s,"
			" SignedHeaders=%s,"
			" Signature=%s",
		creds,
		names,
		sig
	);
	(void) free(sig);
	(void) free(names);
	(void) free(creds);
	return header;
}

static char *
aws_header_credentials_(const AWSSIGN * const sign)
{
	char *substrings[3], *credentials;
	substrings[0] = (char *) sign->access_key;
	substrings[1] = aws_credential_scope_(sign);
	if(!substrings[1])
	{
		fprintf(stderr, "%s: failed to build v4 credentials scope string\n", __FUNCTION__);
		return NULL;
	}
	substrings[2] = NULL;
	credentials = aws_join_char('/', substrings);
	(void) free(substrings[1]);
	return credentials;
}

static char *
aws_credential_scope_(const AWSSIGN * const sign)
{
	char *substrings[5], *scope;
	substrings[0] = aws_timef(SIMPLE_DATE_FORMAT_STR, &(sign->timestamp));
	if(!substrings[0])
	{
		fprintf(stderr, "%s: failed to format v4 timestamp as string\n", __FUNCTION__);
		return NULL;
	}
	substrings[1] = (char *) sign->region;
	substrings[2] = (char *) sign->service;
	substrings[3] = AWS4_REQUEST;
	substrings[4] = NULL;
	scope = aws_join_char('/', substrings);
	(void) free(substrings[0]);
	return scope;
}

/**
 * allocates and returns a string containing the lower-case names of each of
 * the passed-in list of HTTP headers.
 * pass in only the list of headers which should be signed.
 * returns NULL on failure.
 */
static char *
aws_signed_header_names_(struct curl_slist * const headers)
{
	/* TODO: this gets called twice with identical arguments. memoize? */
	struct curl_slist *names, *sorted_names;
	char *all_names;
	names = aws_curl_slist_map_data(aws_http_header_name, headers);
	if(!names)
	{
		fprintf(stderr, "%s: failed to get header names from header list\n", __FUNCTION__);
		return NULL;
	}
	sorted_names = aws_curl_slist_sort_inplace(strcasecmp, names);
	if(!sorted_names)
	{
		(void) aws_curl_slist_free(&names);
		fprintf(stderr, "%s: failed to sort header names\n", __FUNCTION__);
		return NULL;
	}
	all_names = aws_strtolower_inplace(aws_curl_slist_join_char(';', sorted_names));
	if(!all_names)
	{
		(void) aws_curl_slist_free(&sorted_names);
		fprintf(stderr, "%s: failed to join header names\n", __FUNCTION__);
		return NULL;
	}
	(void) aws_curl_slist_free(&sorted_names);
	return all_names;
}

static char *
aws_signature_v4_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	uint8_t * const digest = aws_signature_v4_digest_(sign, headers);
	if(!digest)
	{
		fprintf(stderr, "%s: failed to compute v4 digest\n", __FUNCTION__);
		return NULL;
	}
	char * const digest_hex = aws_hex_(SHA256_DIGEST_LENGTH, digest);
	(void) free(digest);
	return digest_hex;
}

static uint8_t *
aws_signature_v4_digest_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	char *s = aws_string_to_sign_(sign, headers);
	if(!s)
	{
		fprintf(stderr, "%s: failed to build v4 string to sign\n", __FUNCTION__);
		return NULL;
	}
	uint8_t *key = aws_derived_signing_key_(sign);
	if(!key)
	{
		(void) free(s);
		fprintf(stderr, "%s: failed to derive v4 signing key\n", __FUNCTION__);
		return NULL;
	}
	uint8_t * const digest = aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key, s);
	(void) free(key);
	(void) free(s);
	return digest;
}

static uint8_t *
aws_derived_signing_key_(const AWSSIGN * const sign)
{
	char *date, *secret;
	uint8_t *key1, *key2, *key3, *key4;
	date = aws_timef(SIMPLE_DATE_FORMAT_STR, &(sign->timestamp));
	if(!date)
	{
		return NULL;
	}
	secret = aws_strf(SIGNING_KEY "%s", sign->secret_key);
	if(!secret)
	{
		(void) free(date);
		return NULL;
	}
	key1 = aws_hmac_sha256_(strlen(secret), (uint8_t *) secret, date);
	(void) free(secret);
	(void) free(date);
	if(!key1)
	{
		return NULL;
	}
	key2 = aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key1, sign->region ? sign->region : AWS_DEFAULT_REGION);
	(void) free(key1);
	if(!key2)
	{
		return NULL;
	}
	key3 = aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key2, sign->service);
	(void) free(key2);
	if(!key3)
	{
		return NULL;
	}
	key4 = aws_hmac_sha256_(SHA256_DIGEST_LENGTH, key3, AWS4_REQUEST);
	(void) free(key3);
	return key4;
}

static char *
aws_string_to_sign_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	char *date, *scope, *request_desc_hex, *s;
	date = aws_http_date(&(sign->timestamp));
	if(!date)
	{
		return NULL;
	}
	scope = aws_credential_scope_(sign);
	if(!scope)
	{
		(void) free(date);
		return NULL;
	}
	request_desc_hex = aws_canonical_request_description_hex_(sign, headers);
	if(!request_desc_hex)
	{
		(void) free(scope);
		(void) free(date);
		return NULL;
	}
	{
		char *substrings[] = {
			AWS_HMAC_SHA256,
			date,
			scope,
			request_desc_hex,
			NULL
		};
		s = aws_join_char('\n', substrings);
		(void) free(request_desc_hex);
		(void) free(scope);
		(void) free(date);
		return s;
	}
}

static char *
aws_canonical_request_description_hex_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	char *request_desc, *request_desc_hex;
	uint8_t *request_desc_hash;
	request_desc = aws_canonical_request_description_(sign, headers);
	if(!request_desc)
	{
		return NULL;
	}
	request_desc_hash = aws_sha256_(request_desc);
	(void) free(request_desc);
	if(!request_desc_hash)
	{
		return NULL;
	}
	request_desc_hex = aws_hex_(SHA256_DIGEST_LENGTH, request_desc_hash);
	(void) free(request_desc_hash);
	return request_desc_hex;
}

static char *
aws_canonical_request_description_(
	const AWSSIGN * const restrict sign,
	struct curl_slist * const restrict headers
) {
	char *canonical_url, *canonical_query, *canonical_headers, *signed_headers, *s;
	canonical_url = aws_canonical_uri_(sign);
	if(!canonical_url)
	{
		return NULL;
	}
	canonical_query = aws_canonical_query_string_(sign);
	if(!canonical_query)
	{
		(void) free(canonical_url);
		return NULL;
	}
	canonical_headers = aws_canonical_headers_description_(headers);
	if(!canonical_headers)
	{
		(void) free(canonical_query);
		(void) free(canonical_url);
		return NULL;
	}
	signed_headers = aws_signed_header_names_(headers);
	if(!signed_headers)
	{
		(void) free(canonical_headers);
		(void) free(canonical_query);
		(void) free(canonical_url);
		return NULL;
	}

	{
		char *substrings[] = {
			sign->method,
			canonical_url,
			canonical_query,
			/* v4 only: */
			canonical_headers,
			signed_headers,
			sign->payloadhash ? sign->payloadhash : UNSIGNED_PAYLOAD,
			NULL
		};
		s = aws_join_char('\n', substrings);
		(void) free(signed_headers);
		(void) free(canonical_headers);
		(void) free(canonical_query);
		(void) free(canonical_url);
		return s;
	}
}

/**
 * what AWS calls a "canonical URI" is really just the
 * normalised path component of the URI, except for S3
 */
static char *
aws_canonical_uri_(const AWSSIGN * const sign)
{
	if(aws_strempty(sign->resource))
	{
		return strdup("/");
	}
	else if(strcmp("s3", sign->service) == 0)
	{
		return aws_normalised_resource_key_(sign->resource);
	}
	else
	{
		return aws_normalised_path_(sign->resource);
	}
}

static char *
aws_normalised_path_(char * const path)
{
	return uri_stralloc(uri_create_str(path, NULL));
}

static char *
aws_normalised_resource_key_(char * const resource_key)
{
	char *src = resource_key;
	char *dst = malloc(strlen(resource_key) + 1), *decoded_key = dst;
	if(!decoded_key)
	{
		return errno = ENOMEM, NULL;
	}
	while(*src)
	{
		if(*src == '%')
		{
			*dst++ = aws_unhex_byte_(*(src + 1), *(src + 2));
			src += 3;
		}
		else
		{
			*dst++ = *src++;
		}
	}
	*dst = '\0';
	return decoded_key;
}

static char *
aws_canonical_query_string_(const AWSSIGN * const sign)
{
	/* TODO : not implemented; not needed for S3 except for pre-signing URLs, which we don't support */
	(void) sign;
	return strdup("");
}

/**
 * returns a newly allocated string, or NULL on failure
 * header list can be NULL (which will result in an empty description)
 */
static char *
aws_canonical_headers_description_(struct curl_slist *headers)
{
	struct curl_slist *sorted_headers, *canonical_headers;
	char *description;
	if(!headers)
	{
		return strdup("");
	}
	sorted_headers = aws_curl_slist_sort(strcasecmp, headers);
	if(!sorted_headers)
	{
		return NULL;
	}
	canonical_headers = aws_curl_slist_map_data(aws_canonical_header_, sorted_headers);
	(void) aws_curl_slist_free(&sorted_headers);
	description = aws_curl_slist_concat(canonical_headers);
	(void) aws_curl_slist_free(&canonical_headers);
	return description;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static char *
aws_canonical_header_(char * const header)
{
	char *name, *value, *hdr_canonical;
	name = aws_canonical_header_name_(header);
	if(!name)
	{
		return NULL;
	}
	value = aws_canonical_header_value_(header);
	if(!value)
	{
		(void) free(name);
		return NULL;
	}
	hdr_canonical = aws_strf("%s:%s\n", name, value);
	(void) free(value);
	(void) free(name);
	return hdr_canonical;
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static char *
aws_canonical_header_name_(char * const header)
{
	return aws_strtolower_inplace(aws_http_header_name(header));
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static char *
aws_canonical_header_value_(char * const h)
{
	char *val, *val_trimmed, *val_canonical;
	val = aws_http_header_value(h);
	if(!val)
	{
		return NULL;
	}
	val_trimmed = aws_trim(' ', val);
	(void) free(val);
	if(!val_trimmed)
	{
		return NULL;
	}
	val_canonical = aws_collapse(' ', val_trimmed);
	(void) free(val_trimmed);
	return val_canonical;
}

/**
 * returns a newly allocated string containing the lower-case ASCII hexa-
 * decimal representation of the first <length> bytes of the input buffer.
 * returns NULL on failure.
 */
static char *
aws_hex_(const size_t length, const uint8_t * const bytes)
{
	char * const hex = "0123456789abcdef";
	const uint8_t *b = bytes;
	char *buffer, *nybble;
	size_t i;
	if(!bytes)
	{
		return errno = EINVAL, NULL;
	}
	nybble = buffer = malloc(2 * length + 1); /* length of zero is OK */
	if(!buffer)
	{
		return errno = ENOMEM, NULL;
	}
	for(i = 0; i < length; i++)
	{
		*nybble++ = hex[(*b >> 4) & 0xF];
		*nybble++ = hex[(*b++) & 0xF];
	}
	*nybble = '\0';
	return buffer;
}

static uint8_t
aws_unhex_byte_(char high, char low)
{
	uint8_t byte = 0;
	if(high >= '0' && high <= '9')
	{
		byte += (high - '0') << 4;
	}
	if(high >= 'a' && high <= 'f')
	{
		byte += (high - 'a' + 10) << 4;
	}
	if(high >= 'A' && high <= 'F')
	{
		byte += (high - 'A' + 10) << 4;
	}
	if(low >= '0' && low <= '9')
	{
		byte += low - '0';
	}
	if(low >= 'a' && low <= 'f')
	{
		byte += low - 'a' + 10;
	}
	if(low >= 'A' && low <= 'F')
	{
		byte += low - 'A' + 10;
	}
	return byte;
}

/**
 * compute the SHA256 hash of the null-terminated input string.
 *
 * allocates and returns a pointer to an unterminated buffer of size
 * SHA256_DIGEST_LENGTH containing binary data.
 * dispose of by passing to free().
 */
static uint8_t *
aws_sha256_(const char * const str)
{
	return aws_sha256_binary_(strlen(str), (const uint8_t *) str);
}

/**
 * compute the SHA256 hash of the given byte buffer.
 *
 * allocates and returns a pointer to an unterminated buffer of size
 * SHA256_DIGEST_LENGTH containing binary data.
 * dispose of by passing to free().
 */
static uint8_t *
aws_sha256_binary_(const size_t data_length, const uint8_t * const data)
{
#ifdef WITH_COMMONCRYPTO
	uint8_t * const digest = malloc(CC_SHA256_DIGEST_LENGTH);
	if(!digest)
	{
		return errno = ENOMEM, NULL;
	}
	return CC_SHA256(data, data_length, digest);
#else
	uint8_t * const digest = malloc(SHA256_DIGEST_LENGTH);
	if(!digest)
	{
		return errno = ENOMEM, NULL;
	}
	return SHA256((const unsigned char *) data, data_length, digest);
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
static uint8_t *
aws_hmac_sha256_(
	const size_t secret_key_length,
	const uint8_t * const restrict secret_key,
	char * const restrict str
) {
	uint8_t *digest;
	if (!secret_key || !str)
	{
		return errno = EINVAL, NULL;
	}
#ifdef WITH_COMMONCRYPTO
	digest = malloc(CC_SHA256_DIGEST_LENGTH);
	if (!digest) return errno = ENOMEM, NULL;
	(void) CCHmac(kCCHmacAlgSHA256, secret_key, secret_key_length, str, strlen(str), digest);
	return digest;
#else
	digest = malloc(EVP_MAX_MD_SIZE); /* use SHA256_DIGEST_LENGTH and avoid realloc? */
	if (!digest)
	{
		return errno = ENOMEM, NULL;
	}
	{
		unsigned int digestlen;
		(void) HMAC(EVP_sha256(), secret_key, secret_key_length, (unsigned char *) str, strlen(str), digest, &digestlen);
		return realloc(digest, digestlen);
	}
#endif
}

/**
 * returns a newly allocated string, or NULL on failure
 */
static char *
aws_create_host_header_(const char * const host)
{
	return aws_strf("Host: %s", host);
}

static int
aws_header_sort_(const void * const a, const void * const b)
{
	return strcmp(*(char **) a, *(char **) b);
}
