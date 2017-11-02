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

#define ACCESS_KEY "AKIAIOSFODNN7EXAMPLE"
#define SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

spec("service/s3") {
	static char * const bucket_name = "libawsclient-dev";
	static char * const bucket_uri = "s3://libawsclient-dev/?region=eu-west-1&access=" ACCESS_KEY "&secret=" SECRET_KEY;

	it("should return a valid pointer when creating an S3 service descriptor from a bucket name") {
		check(aws_s3_create(bucket_name) != NULL);
	}

	it("should return a valid pointer when creating an S3 service descriptor from a complete service URI") {
		check(aws_s3_create_uristr(bucket_uri) != NULL);
	}
}
