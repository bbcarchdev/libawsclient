/* Copyright (c) 2017 BBC
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

#include "bdd-for-c.h"

#include "libawsclient.h"
#include "curl_slist.h"
#include "http.h"

#define METHOD "GET"
#define RESOURCE "README.md"
#define REGION "eu-west-1"
#define ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define AUTH_HEADER_NAME "Authorization"
#define V4_HASH_HEADER_NAME "X-Amz-Content-SHA256"
#define V2_AUTH_HEADER_PREFIX AUTH_HEADER_NAME ": AWS "
#define V4_AUTH_HEADER_PREFIX AUTH_HEADER_NAME ": AWS4-HMAC-SHA256 "
#define CUSTOM_HEADER "X-Custom-Header: value"
#define KNOWN_PAYLOAD ((uint8_t *) "payload")
#define KNOWN_PAYLOAD_LENGTH (7)
#define KNOWN_PAYLOAD_HASH "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
#define KNOWN_PAYLOAD_HASH_LENGTH (64)

static int contains_header_name(const char * const name, struct curl_slist * const headers) {
	struct curl_slist *h = headers;
	while(h && strcmp(name, aws_http_header_name(h->data)) != 0)
		h = h->next;
	return (h != NULL);
}

static int contains_header_prefix(const char * const prefix, struct curl_slist * const headers) {
	struct curl_slist *h = headers;
	while(h && strncmp(prefix, h->data, strlen(prefix)) != 0)
		h = h->next;
	return (h != NULL);
}

/* Depends on bucket_spec and request_spec passing */

spec("sign") {
	it("should compute a payload hash correctly") {
		char *hash = aws_sign_payload_hash(KNOWN_PAYLOAD_LENGTH, KNOWN_PAYLOAD);
		int comparison = memcmp(hash, KNOWN_PAYLOAD_HASH, KNOWN_PAYLOAD_HASH_LENGTH);
		check(comparison == 0);
	}

	context("old api") {
		it("should return an auth header when signing an empty list of headers using the old v2 API") {
			struct curl_slist *hs = aws_s3_sign(METHOD, RESOURCE, ACCESS_KEY, SECRET_KEY, NULL);
			check(hs != NULL);
			check(contains_header_name(AUTH_HEADER_NAME, hs));
		}

		it("should return an auth header when signing a non-empty list of headers using the old v2 API") {
			struct curl_slist *hs = curl_slist_append(NULL, CUSTOM_HEADER);
			hs = aws_s3_sign(METHOD, RESOURCE, ACCESS_KEY, SECRET_KEY, hs);
			check(hs != NULL);
			check(contains_header_name(AUTH_HEADER_NAME, hs));
		}
	}

	context("new api") {
		static AWSSIGN sign = {};

		before_each() {
			sign.version = AWS_SIGN_VERSION_DEFAULT;
			sign.size = sizeof sign;
			sign.timestamp = time(NULL);
			sign.method = METHOD;
			sign.resource = RESOURCE;
			sign.access_key = ACCESS_KEY;
			sign.secret_key = SECRET_KEY;
			sign.token = NULL;
			sign.region = REGION;
			sign.service = "s3"; /* used to build the v4 signature string */
			sign.payloadhash = NULL;
		}

		it("should choose v4 when signing with the default signature version") {
			struct curl_slist *hs = curl_slist_append(NULL, CUSTOM_HEADER);
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}

		it("should return a v2 auth header when asked to sign with v2") {
			sign.version = AWS_SIGN_VERSION_2;
			struct curl_slist *hs = curl_slist_append(NULL, CUSTOM_HEADER);
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_prefix(V2_AUTH_HEADER_PREFIX, hs));
		}

		it("should return the v4 auth headers when asked to sign with v4") {
			sign.version = AWS_SIGN_VERSION_4;
			struct curl_slist *hs = curl_slist_append(NULL, CUSTOM_HEADER);
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_name(V4_HASH_HEADER_NAME, hs));
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}

		it("should return the v4 auth headers when signing with v4 and a given payload hash") {
			sign.version = AWS_SIGN_VERSION_4;
			sign.payloadhash = KNOWN_PAYLOAD_HASH;
			struct curl_slist *hs = curl_slist_append(NULL, CUSTOM_HEADER);
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_name(V4_HASH_HEADER_NAME, hs));
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}
	}
}
