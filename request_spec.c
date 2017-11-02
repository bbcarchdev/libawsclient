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
#include "http.h"

/* example keys taken from AWS documentation */
#define ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

/* Depends on bucket_spec passing */

spec("request") {
	static AWSREQUEST *request;

	before() {
		AWSS3BUCKET *s3;
		s3 = aws_s3_create_uristr("s3://libawsclient-dev/?region=eu-west-1&access=" ACCESS_KEY "&secret=" SECRET_KEY);
		request = aws_s3_request_create(s3, "README.md", "GET");
	}

	it("should return a valid pointer when creating a request") {
		check(request != NULL);
	}

	it("should initialise a valid curl handle") {
		check(aws_request_curl(request) != NULL);
	}

	context("finalisation") {
		it("should report no error occurred (return 0) when asked to sign a request") {
			check(aws_request_finalise(request) == 0);
		}

		it("should add an Authorization header to the request") {
			aws_request_finalise(request);
			struct curl_slist *h = aws_request_headers(request);
			while(h && strcmp("Authorization", aws_http_header_name(h->data)) != 0)
				h = h->next;
			check(h != NULL);
		}

		it("should add an X-Amz-Content-SHA256 header to the request") {
			aws_request_finalise(request);
			struct curl_slist *h = aws_request_headers(request);
			while(h && strcmp("X-Amz-Content-SHA256", aws_http_header_name(h->data)) != 0)
				h = h->next;
			check(h != NULL);
		}
	}
}
