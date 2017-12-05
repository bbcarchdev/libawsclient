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

#include <assert.h>
#include "bdd-for-c.h"

#include "libawsclient.h"
#include "http.h"

#define METHOD "GET"
#define RESOURCE "file.txt"

#define CUSTOM_HEADER "X-Custom-Header: value"

/* Depends on bucket_spec passing; finalisation depends on sign_spec passing */

spec("request") {
	static AWSS3BUCKET *s3;

	before() {
		s3 = aws_s3_create("bucket");
		assert(s3 != NULL);
	}

	context("initialisation") {
		it("should return a valid pointer upon creation") {
			check(aws_s3_request_create(s3, RESOURCE, METHOD) != NULL);
		}

		it("should initialise a valid curl handle") {
			AWSREQUEST *request = aws_s3_request_create(s3, RESOURCE, METHOD);
			assert(request != NULL);
			check(aws_request_curl(request) != NULL);
		}
	}

	context("accessors") {
		static AWSREQUEST *request;

		before() {
			request = aws_s3_request_create(s3, RESOURCE, METHOD);
			assert(request != NULL);
		}

		it("should round-trip the header list") {
			struct curl_slist *headers = curl_slist_append(NULL, CUSTOM_HEADER);
			assert(headers != NULL);
			check(aws_request_set_headers(request, headers) == 0);
			check(aws_request_headers(request) == headers);
		}
	}

	context("finalisation") {
		it("should successfully finalise an anonymous request") {
			AWSREQUEST *request = aws_s3_request_create(s3, RESOURCE, METHOD);
			assert(request != NULL);
			check(aws_request_finalise(request) == 0);
		}

		it("should sign a request with credentials during finalisation") {
			AWSS3BUCKET *s3_cred = aws_s3_create_uristr("s3://bucket/?access=1&secret=2");
			assert(s3_cred != NULL);
			AWSREQUEST *request = aws_s3_request_create(s3_cred, RESOURCE, METHOD);
			assert(request != NULL);
			check(aws_request_finalise(request) == 0);
			/* the following is a proxy for checking that aws_sign() gets called */
			struct curl_slist *h = aws_request_headers(request);
			while(h && strcmp("Authorization", aws_http_header_name(h->data)) != 0)
				h = h->next;
			check(h != NULL);
		}

		it("should not allow modification of a request after finalisation") {
			AWSREQUEST *request = aws_s3_request_create(s3, RESOURCE, METHOD);
			struct curl_slist *headers = curl_slist_append(NULL, CUSTOM_HEADER);
			assert(request != NULL);
			assert(headers != NULL);
			assert(aws_request_finalise(request) == 0);
			check(aws_request_set_headers(request, headers) != 0);
		}
	}

	context("execution") {
		it("should successfully perform a synchronous request") {
			AWSREQUEST *request = aws_s3_request_create(s3, RESOURCE, METHOD);
			assert(request != NULL);
			check(aws_request_perform(request) == 0);
		}
	}
}

CURLcode
curl_easy_perform(CURL *ch)
{
	(void) ch;
	return 0;
}
