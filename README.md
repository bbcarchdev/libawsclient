This is a small client library for making requests to Amazon S3 and other
services which expose the same API (such as [RADOS](http://ceph.com/docs/master/rados/)).

It was originally written as part of [Anansi](https://github.com/bbcarchdev/anansi),
but has been split into a separate project to facilitiate reuse.

It depends upon [libcurl](http://curl.haxx.se/libcurl/) and
[OpenSSL](https://www.openssl.org/).

Note that at present this is not a standalone configurable project - it
is currently built as a convenience library within existing projects, but
this will likely change in the future.
