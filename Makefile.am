## Author: Mo McRoberts <mo.mcroberts@bbc.co.uk>
##
## Copyright (c) 2014-2015 BBC
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.

ACLOCAL_AMFLAGS = -I m4

DIST_SUBDIRS = m4

EXTRA_DIST = README.md

AM_CPPFLAGS = @AM_CPPFLAGS@ $(LIBCURL_CPPFLAGS) $(OPENSSL_CPPFLAGS)

lib_LTLIBRARIES = libawsclient.la

libawsclient_la_SOURCES = libawsclient.h libs3client.h p_libawsclient.h \
	base64.c sign.c bucket.c request.c

libawsclient_la_LIBADD = \
	$(LIBCURL_LOCAL_LIBS) $(LIBCURL_LIBS) \
	$(OPENSSL_LOCAL_LIBS) $(OPENSSL_LIBS) \
	$(LIBURI_LOCAL_LIBS) $(LIBURI_LIBS)

libawsclient_la_LDFLAGS = -avoid-version

checkout:
	@true
