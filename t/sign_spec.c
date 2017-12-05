/**
 * Copyright (c) 2017 BBC
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

#include <assert.h>
#include "bdd-for-c.h"

#include "p_libawsclient.h"

#define METHOD "GET"
#define RESOURCE "README.md"
#define REGION "eu-west-1"
#define AUTH_HEADER_NAME "Authorization"
#define V4_HASH_HEADER_NAME "X-Amz-Content-SHA256"
#define V2_AUTH_HEADER_PREFIX AUTH_HEADER_NAME ": AWS "
#define V4_AUTH_HEADER_PREFIX AUTH_HEADER_NAME ": AWS4-HMAC-SHA256 "
#define CUSTOM_HEADER "X-Custom-Header: value"
#define KNOWN_PAYLOAD ((uint8_t *) "payload")
#define KNOWN_PAYLOAD_LENGTH (7)
#define KNOWN_PAYLOAD_HASH "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
#define KNOWN_PAYLOAD_HASH_LENGTH (64)

/* example values taken from AWS documentation */
#define ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define SESSION_TOKEN "\
AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW\
LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd\
QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU\
9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz\
+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="

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
		static struct curl_slist *hs;
		static AWSSIGN sign = {};

		before_each() {
			hs = curl_slist_append(NULL, CUSTOM_HEADER);
			sign.version = AWS_SIGN_VERSION_DEFAULT;
			sign.size = sizeof sign;
			sign.service = "s3";
			sign.timestamp = time(NULL);
			sign.method = METHOD;
			sign.resource = RESOURCE;
			sign.access_key = ACCESS_KEY;
			sign.secret_key = SECRET_KEY;
			sign.token = NULL;
			sign.region = NULL;
			sign.payloadhash = NULL;
		}

		after_each() {
			curl_slist_free_all(hs);
		}

		it("should choose v2 by default when signing with minimal fields") {
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_prefix(V2_AUTH_HEADER_PREFIX, hs));
		}

		it("should choose v4 by default when signing with a region") {
			sign.region = REGION;
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_name(V4_HASH_HEADER_NAME, hs));
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}

		it("should choose v4 by default when signing with a session token") {
			sign.token = SESSION_TOKEN;
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_name(V4_HASH_HEADER_NAME, hs));
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}

		it("should choose v4 by default when signing with a payload hash") {
			sign.payloadhash = KNOWN_PAYLOAD_HASH;
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_name(V4_HASH_HEADER_NAME, hs));
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}

		it("should return a v2 auth header when asked to sign with v2, even in the presence of v4 fields") {
			sign.version = AWS_SIGN_VERSION_2;
			sign.region = REGION;
			sign.token = SESSION_TOKEN;
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_prefix(V2_AUTH_HEADER_PREFIX, hs));
		}

		it("should return the v4 auth headers when asked to sign with v4") {
			sign.version = AWS_SIGN_VERSION_4;
			hs = aws_sign(&sign, hs);
			check(hs != NULL);
			check(contains_header_name(V4_HASH_HEADER_NAME, hs));
			check(contains_header_prefix(V4_AUTH_HEADER_PREFIX, hs));
		}
	}
}
