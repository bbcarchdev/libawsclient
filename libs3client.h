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

#ifndef LIBS3CLIENT_H_
# define LIBS3CLIENT_H_                 1

# warning <libs3client.h> is deprecated; use <libawsclient.h> instead.

# include <libawsclient.h>

typedef struct aws_s3_descriptor_struct S3BUCKET;
typedef struct aws_request_struct S3REQUEST;

# define s3_create(bucket)             aws_s3_create(bucket)
# define s3_destroy(bucket)            aws_s3_destroy(bucket)
# define s3_set_logger(bucket, fn)     aws_s3_set_logger(bucket, fn)
# define s3_set_bucket(bucket, name)   aws_s3_set_bucket(bucket, name)
# define s3_set_access(bucket, key)    aws_s3_set_access(bucket, key)
# define s3_set_secret(bucket, key)    aws_s3_set_secret(bucket, key)
# define s3_set_endpoint(bucket, host) aws_s3_set_endpoint(bucket, host)
# define s3_set_basepath(bucket, path) aws_s3_set_basepath(bucket, path)
# define s3_request_create(bucket, resource, method) \
	aws_s3_request_create(bucket, resource, method)
# define s3_request_destroy(request)   aws_request_destroy(request)
# define s3_request_finalise(request)  aws_request_finalise(request)
# define s3_request_perform(request)   aws_request_perform(request)
# define s3_request_curl(request)      aws_request_curl(request)
# define s3_request_headers(request)   aws_request_headers(request)
# define s3_request_set_headers(request, headers) \
	aws_request_set_headers(request, headers)
# define s3_sign(method, resource, access_key, secret, headers) \
	aws_s3_sign(method, resource, access_key, secret, headers)

#endif /*!LIBS3CLIENT_H_*/
