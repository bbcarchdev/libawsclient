This is a small client library for making requests to Amazon S3 and other
services which expose the same API (such as [RADOS](http://ceph.com/docs/master/rados/)).

It was originally written as part of [Anansi](https://github.com/bbcarchdev/anansi),
but has been split into a separate project to facilitiate reuse.

It depends upon [libcurl](http://curl.haxx.se/libcurl/), [liburi](https://bbcarchdev.github.io/liburi/) and
[OpenSSL](https://www.openssl.org/) (except on Mac OS X, where CommonCrypto is used instead).

libawsclient URIs have the following form (all parameters are optional if the defaults are sufficient or the information is supplied through specific setter calls):

```

s3://ACCESSKEY:SECRETKEY@BUCKET/RESOURCE?endpoint=HOSTNAME&region=REGION&ver=AUTHVER&token=TOKEN

```

In the above:

| Name        | Description                                             |
| ----------- | ------------------------------------------------------- |
| `ACCESSKEY` | The AWS access key                                      |
| `SECRETKEY` | The AWS secret key     	                                |
| `HOSTNAME`  | The endpoint name (defaulting to `s3.amazonaws.com` for S3 requests) |
| `REGION`    | The region name for v4 authentication, e.g., `us-west-1` |
| `AUTHVER`   | The authentication mechanism to use; defaults to '2' unless a `REGION` or `TOKEN` are supplied, in which case '4' |
| `TOKEN`     | An AWS session token, if you have one                  |
| `BUCKET`    | The name of the S3 bucket to access                    |
| `RESOURCE`  | The path of the resource within a bucket               |

