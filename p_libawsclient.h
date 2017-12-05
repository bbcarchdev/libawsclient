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

#ifndef P_LIBAWSCLIENT_H_
# define P_LIBAWSCLIENT_H_             1

# include <alloca.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stdarg.h>
# include <stddef.h>
# include <string.h>
# include <strings.h>
# include <time.h>
# include <errno.h>
# include <ctype.h>
# include <syslog.h>
# include <sys/types.h>

# ifdef WITH_COMMONCRYPTO
#  include <CommonCrypto/CommonCrypto.h>
# else
#  include <openssl/hmac.h>
#  include <openssl/evp.h>
#  include <openssl/bio.h>
#  include <openssl/buffer.h>
#  include <openssl/sha.h>
# endif

# include <curl/curl.h>
# include <liburi.h>

# include "libawsclient.h"

# define AWS_DEFAULT_REGION            "us-east-1"
# define S3_DEFAULT_ENDPOINT           "s3.amazonaws.com"
# define S3_REGIONAL_ENDPOINT_FORMAT   "s3-%s.amazonaws.com"
# define S3_DUALSTACK_ENDPOINT_FORMAT  "s3.dualstack.%s.amazonaws.com"

# define HTTP_DATE_FORMAT              "%a, %d %b %Y %H:%M:%S GMT"
# define HTTP_DATE_FORMAT_STR          "%a, %d %b %Y %H:%M:%S GMT"
# define LONG_DATE_FORMAT_STR          "%Y%m%dT%H%M%SZ"
# define SIMPLE_DATE_FORMAT_STR        "%Y%m%d"

# define HTTP_DATE_LENGTH              29

# ifndef SHA1_DIGEST_LENGTH
#  define SHA1_DIGEST_LENGTH           20
# endif
# ifndef SHA256_DIGEST_LENGTH
#  define SHA256_DIGEST_LENGTH         32
# endif

# define EQ "="
# define NEWLINE                       "\n"

# define EMPTY_STRING_SHA256 \
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# define AUTHORIZATION                 "Authorization"
# define AWS_HMAC_SHA256               "AWS4-HMAC-SHA256"
# define AWS4_REQUEST                  "aws4_request"
# define CREDENTIAL                    "Credential"
# define SIGNATURE                     "Signature"
# define SIGNED_HEADERS                "SignedHeaders"
# define SIGNING_KEY                   "AWS4"
# define UNSIGNED_PAYLOAD              "UNSIGNED-PAYLOAD"
# define X_AMZ_ALGORITHM               "X-Amz-Algorithm"
# define X_AMZ_CONTENT_SHA256          "X-Amz-Content-SHA256"
# define X_AMZ_CREDENTIAL              "X-Amz-Credential"
# define X_AMZ_SIGNATURE               "X-Amz-Signature"
# define X_AMZ_SIGNED_HEADERS          "X-Amz-SignedHeaders"

struct aws_s3_bucket_struct
{
	aws_signature_version version;
	char *bucket;
	char *access;
	char *secret;
	char *endpoint; /* [user [":" pass] "@"] host [":" port] */
	char *basepath;
	char *region;
	char *token;
	void (*logger)(int prio, const char *format, va_list ap);
};

struct aws_request_struct
{
	AWSS3BUCKET *bucket;
	char *resource;
	char *method; /* not copied by curl_easy_setopt < 7.17.0 */
	char *url; /* not copied by curl_easy_setopt < 7.17.0 */
	CURL *ch;
	struct curl_slist *headers; /* not copied by curl_easy_setopt */
	int finalised;
};

int aws_s3_ensure_endpoint_is_specified_(AWSS3BUCKET * const s3);
void aws_s3_logf_(AWSS3BUCKET *s3, int prio, const char *format, ...);

int aws_sign_credentials_are_anonymous(const AWSSIGN * const sign);

int aws_base64_encode_(const void *data, int size, uint8_t *buffer);
uint8_t *aws_base64_decode_(uint8_t *str, void *data, int *datalen);

/* HTTP utilities (http.c) */

struct curl_slist *aws_set_http_header(struct curl_slist *headers, char *header);
char *aws_http_header_name(char *header) AWS_MALLOC;
char *aws_http_header_value(char *header) AWS_MALLOC;
size_t aws_http_header_name_length(char *header) AWS_PURE;
char *aws_create_http_date_header(const time_t *timestamp) AWS_MALLOC;
char *aws_http_date(const time_t *timestamp) AWS_MALLOC;
char *aws_http_date_tm(struct tm *time) AWS_MALLOC;

/* Memory-management utilities (mem.c) */

void *aws_safe_free(void ** const ptr);
void *aws_safe_free_list(void *** const restrict list_ptr);

/* String manipulation (string.c) */

char *aws_trim_(char c, const char *str) AWS_MALLOC;
char *aws_collapse(char c, char *str) AWS_MALLOC;
char *aws_strtolower_inplace(char *str);
char *aws_join_char(char delim, char **list) AWS_MALLOC;
char *aws_stradd(char *dst, char *src);
char *aws_strf(const char *format, ...) AWS_FORMAT_STRING_1_2 AWS_MALLOC;
char *aws_timef(const char *format, const time_t *date) AWS_FORMAT_TIME_1 AWS_MALLOC;
char *aws_brokentimenf(const char *format, size_t length, struct tm *brokentime) AWS_FORMAT_TIME_1 AWS_ALLOC_2 AWS_MALLOC;
int aws_strempty(char *str);

/* libcurl string list manipulation (curl_slist.c) */

struct curl_slist *aws_curl_slist_create_nocopy(char **strs);
struct curl_slist *aws_curl_slist_copy(struct curl_slist *list);
struct curl_slist *aws_curl_slist_free(struct curl_slist **list_ptr);
struct curl_slist *aws_curl_slist_sort(int (*compare_f)(const char *, const char *), struct curl_slist *list);
struct curl_slist *aws_curl_slist_sort_inplace(int (*compare_f)(const char *, const char *), struct curl_slist *list);
struct curl_slist *aws_curl_slist_map_data(char *(*map_f)(char *), struct curl_slist *list);
struct curl_slist *aws_curl_slist_fold_left(struct curl_slist *(*fold_f)(struct curl_slist *, char *), struct curl_slist *list1, struct curl_slist *list2);
char *aws_curl_slist_concat(struct curl_slist *list);
char *aws_curl_slist_join_char(char delim, struct curl_slist *list);
void aws_curl_slist_dump(struct curl_slist *list);

#endif /*!P_LIBAWSCLIENT_H_*/
