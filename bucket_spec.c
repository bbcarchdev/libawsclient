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
#include <liburi.h>
#include "bdd-for-c.h"

#include "libawsclient.h"

#define BUCKET_NAME "example-bucket"
#define BUCKET_URI "s3://" BUCKET_NAME "/"
#define ENDPOINT "user:pass@[::1]:9990"
#define ENDPOINT_URI_ENCODED "user%3Apass%40%5B%3A%3A1%5D%3A9990"
#define REGION "eu-west-1"
#define REGION_URI_ENCODED "eu-west-1"

/* example values taken from AWS documentation */
#define ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define SESSION_TOKEN "\
AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW\
LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd\
QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU\
9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz\
+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="

void logging_func_(int priority, const char *format, va_list ap) {}
URI *uri_create_ascii(const char *restrict uristr, const URI *restrict uri);


spec("service/s3") {
	it("should return a valid pointer when creating an S3 service descriptor from a bucket name") {
		check(aws_s3_create(BUCKET_NAME) != NULL);
	}

	it("should return a valid pointer when creating an S3 service descriptor from a service URI object") {
		URI *uri = uri_create_ascii(BUCKET_URI, NULL);
		assert(uri != NULL);
		check(aws_s3_create_uri(uri) != NULL);
	}

	it("should return a valid pointer when creating an S3 service descriptor from a service URI string") {
		check(aws_s3_create_uristr(BUCKET_URI) != NULL);
	}

	it("should successfully dispose of a service descriptor") {
		AWSS3BUCKET *s3 = aws_s3_create(BUCKET_NAME);
		assert(s3 != NULL);
		check(aws_s3_destroy(s3) == 0);
	}

	it("should return the default version when no version parameter is supplied") {
		AWSS3BUCKET *s3 = aws_s3_create_uristr(BUCKET_URI);
		assert(s3 != NULL);
		check(aws_s3_version(s3) == AWS_SIGN_VERSION_DEFAULT);
	}

	context("bucket URI parameters") {
		it("should retain the bucket name from the bucket URI") {
			AWSS3BUCKET *s3 = aws_s3_create_uristr(BUCKET_URI);
			assert(s3 != NULL);
			check(strcmp(BUCKET_NAME, aws_s3_bucket_name(s3)) == 0);
		}

		it("should retain the endpoint parameter from the bucket URI") {
			AWSS3BUCKET *s3 = aws_s3_create_uristr(BUCKET_URI "?endpoint=" ENDPOINT_URI_ENCODED);
			assert(s3 != NULL);
			check(strcmp(ENDPOINT, aws_s3_endpoint(s3)) == 0);
		}

		it("should retain the region parameter from the bucket URI") {
			AWSS3BUCKET *s3 = aws_s3_create_uristr(BUCKET_URI "?region=" REGION_URI_ENCODED);
			assert(s3 != NULL);
			check(strcmp(REGION, aws_s3_region(s3)) == 0);
		}

		it("should retain the version parameter from the bucket URI") {
			AWSS3BUCKET *s3 = aws_s3_create_uristr(BUCKET_URI "?ver=2");
			assert(s3 != NULL);
			check(aws_s3_version(s3) == AWS_SIGN_VERSION_2);
		}
	}

	context("accessors") {
		static AWSS3BUCKET *s3;

		before() {
			s3 = aws_s3_create(BUCKET_NAME);
			assert(s3 != NULL);
		}

		it("should set the logging function") {
			check(aws_s3_set_logger(s3, logging_func_) == 0);
		}

		it("should set the access key") {
			check(aws_s3_set_access(s3, ACCESS_KEY) == 0);
		}

		it("should set the secret key") {
			check(aws_s3_set_secret(s3, SECRET_KEY) == 0);
		}

		it("should set the session token") {
			check(aws_s3_set_token(s3, SESSION_TOKEN) == 0);
		}

		it("should round-trip the bucket name") {
			const char *value = "name";
			check(aws_s3_set_bucket_name(s3, value) == 0);
			check(strcmp(value, aws_s3_bucket_name(s3)) == 0);
		}

		it("should round-trip the endpoint value") {
			const char *value = "endpoint";
			check(aws_s3_set_endpoint(s3, value) == 0);
			check(strcmp(value, aws_s3_endpoint(s3)) == 0);
		}

		it("should round-trip the basepath value") {
			const char *value = "basepath";
			check(aws_s3_set_basepath(s3, value) == 0);
			check(strcmp(value, aws_s3_basepath(s3)) == 0);
		}

		it("should round-trip the region value") {
			const char *value = "region";
			check(aws_s3_set_region(s3, value) == 0);
			check(strcmp(value, aws_s3_region(s3)) == 0);
		}

		it("should round-trip the signature version") {
			const aws_signature_version value = AWS_SIGN_VERSION_4;
			check(aws_s3_set_version(s3, value) == 0);
			check(aws_s3_version(s3) == value);
		}
	}
}
