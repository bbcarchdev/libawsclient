#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <curl/curl.h>
#include "libawsclient.h"
#include "attributes.h"

static const char *endpoint, *accesskey, *secretkey, *objectkey, *token, *region;
static char *bucketuri;
static const char *short_progname = "s3cat";
static int verbose;
aws_signature_version_t authversion;

static int process_args(int argc, char **argv);
static void usage(void);
static void logger(int prio, const char *format, va_list ap);

int
main(int argc, char **argv)
{
	AWSS3BUCKET *bucket;
	AWSREQUEST *request;
	CURL *ch;
	int r;
	long status;

	if(process_args(argc, argv))
	{
		return EXIT_FAILURE;
	}
	bucket = aws_s3_create_uristr(bucketuri);
	if(!bucket)
	{
		fprintf(stderr, "%s: failed to create S3 bucket object from <%s>\n", short_progname, bucketuri);
		return EXIT_FAILURE;
	}
	if(verbose)
	{
		fprintf(stderr, "%s: fetching object '%s' from <s3://%s>\n", short_progname, objectkey, aws_s3_bucket(bucket));
	}
	aws_s3_set_logger(bucket, logger);
	if(accesskey)
	{
		aws_s3_set_access(bucket, accesskey);
	}
	if(secretkey)
	{
		aws_s3_set_secret(bucket, secretkey);
	}
	if(endpoint)
	{
		aws_s3_set_endpoint(bucket, endpoint);
	}
	if(token)
	{
		aws_s3_set_token(bucket, token);
	}
	if(region)
	{
		aws_s3_set_region(bucket, region);
	}
	if(authversion)
	{
		aws_s3_set_version(bucket, authversion);
	}
	request = aws_s3_request_create(bucket, objectkey, "GET");
	if(!request)
	{
		fprintf(stderr, "%s: failed to create S3 request object for <s3://%s/%s>\n", short_progname, aws_s3_bucket(bucket), objectkey);
		aws_s3_destroy(bucket);
		free(bucketuri);
		return EXIT_FAILURE;
	}
	ch = aws_request_curl(request);
	curl_easy_setopt(ch, CURLOPT_HEADER, 0);
	curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1);
	if(verbose)
	{
		curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
	}
	status = 0;
	r = EXIT_SUCCESS;
	if(aws_request_perform(request) != CURLE_OK)
	{
		fprintf(stderr, "%s: failed to perform request\n", short_progname);
		r = EXIT_FAILURE;
	}
	else if(curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
	{
		fprintf(stderr, "%s: failed to obtain HTTP response code\n", short_progname);
		r = EXIT_FAILURE;
	}
	else if(!status)
	{
		if(curl_easy_getinfo(ch, CURLINFO_OS_ERRNO, &status) != CURLE_OK)
		{
			fprintf(stderr, "%s: failed to obtain operating system error code\n", short_progname);
		}
		else
		{
			fprintf(stderr, "%s: HTTP request failed: %s\n", short_progname, strerror(status));
		}
		r = EXIT_FAILURE;
	}
	else if(status != 200)
	{
		fprintf(stderr, "%s: HTTP request failed with status %d\n", short_progname, (int) status);
		r = EXIT_FAILURE;
	}
	aws_request_destroy(request);
	aws_s3_destroy(bucket);
	return r;
}

static int
process_args(int argc, char **argv)
{
	char *t;
	int c;
	intmax_t n;

	t = strrchr(argv[0], '/');
	if(t && t[1])
	{
		t++;
		short_progname = t;
	}
	else
	{
		short_progname = argv[0];
	}
	while((c = getopt(argc, argv, "a:de:hk:r:s:t:v:?")) != -1)
	{
		switch(c)
		{
		case 'h':
		case '?':
			usage();
			exit(EXIT_SUCCESS);
		case 'd':
			verbose = 1;
			break;
		case 'a':
			accesskey = optarg;
			break;
		case 's':
			secretkey = optarg;
			break;
		case 'e':
			endpoint = optarg;
			break;
		case 'k':
			objectkey = optarg;
			break;
		case 't':
			token = optarg;
			break;
		case 'r':
			region = optarg;
			break;
		case 'v':
			n = strtoimax(optarg, NULL, 10);
			if(n != 2 && n != 4)
			{
				fprintf(stderr, "%s: version must be '2' or '4'\n", short_progname);
				return -1;
			}
			authversion = n;
			break;
		default:
			usage();
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if(argc != 1)
	{
		usage();
		return -1;
	}
	if(!authversion && (token || region))
	{
		authversion = 4;
	}
	if(strncmp(argv[0], "s3:", 3))
	{
		fprintf(stderr, "%s: URI provided does not use the \"s3\" scheme (<s3://...>)\n", short_progname);
		usage();
		return -1;
	}
	bucketuri = strdup(argv[0]);
	t = strchr(argv[0] + 5, '/');
	if(!t)
	{
		fprintf(stderr, "%s: no object key provided in S3 URL\n", short_progname);
		usage();
		return -1;
	}
	*t = 0;
	if(!objectkey)
	{
		objectkey = t + 1;
		t = strchr(objectkey, '?');
		if(t)
		{
			*t = 0;
		}
	}
	return 0;
}

static void
usage(void)
{
	printf("Usage: %s OPTIONS s3://[ACCESS:SECRET@]BUCKET/OBJECTKEY[?PARAMS]"
		"\n"
		"OPTIONS is one or more of:\n"
		"  -h             Print this message and exit\n"
		"  -d             Enable debugging output\n"
		"  -a KEY         Specify access key\n"
		"  -s KEY         Specify secret key\n"
		"  -t TOKEN       Specify the session token (implies -v4)\n"
		"  -e HOSTNAME    Specify alternative S3 endpoint\n"
		"  -v VER         Specify the signature version (2 or 4).\n"
		"                   Overrides any implied version.\n"
		"  -r REGION      Specify the AWS region (implies -v4 and\n"
		"                   -e s3-REGION.amazonaws.com)\n"
		"  -k KEY         Specify an object key (i.e. a resource path, ignores any in\n"
		"                   the URI). Object keys do not begin with a '/'.\n"
		"                   Use this if e.g. your object key has a literal '?' in it.\n",
		short_progname);
}

static void
logger(int prio, const char *format, va_list ap)
{
	fprintf(stderr, "%s: <%d> ", short_progname, prio);
	vfprintf(stderr, format, ap);
}

