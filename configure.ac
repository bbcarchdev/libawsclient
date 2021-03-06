##  Spindle: The RES Linked Open Data Aggregator
##
##  Author: Mo McRoberts
##
##  Copyright (c) 2014-2015 BBC
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

AC_INIT([libawsclient],m4_esyscmd([/bin/sh m4/get-version.sh]),[RESFeedback@bbc.co.uk],,[https://github.com/bbcarchdev/libawsclient])
PACKAGE_DESC='A library for interfacing with Amazon Web Services'
AC_SUBST([PACKAGE_DESC])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

AC_CONFIG_HEADER([config.h])

BT_PROG_XCODE
AC_PROG_CC([clang c99 gcc cc])
BT_PROG_CC_WARN
BT_PROG_CC_DEBUG
AC_PROG_CC_C99

LT_INIT

BT_ENABLE_POSIX_FULL
AC_SYS_LARGEFILE

BT_REQUIRE_LIBCURL

BT_CHECK_COMMONCRYPTO(,[
	BT_REQUIRE_OPENSSL
])

BT_REQUIRE_LIBURI

BT_DEFINE_PREFIX

AC_CHECK_FUNCS_ONCE([stpcpy vasprintf vsnprintf vsyslog])

AC_CONFIG_FILES([Makefile
m4/Makefile
libawsclient.pc
libawsclient-uninstalled.pc
])

AC_OUTPUT
