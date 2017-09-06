#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "libawsclient.h"

static const char *endpoint, *accesskey, *secretkey, *resource;
static char *bucketuri;
static const char *short_progname = "s3cat";
static int verbose;

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
		return 1;
	}
	bucket = aws_s3_create_uristr(bucketuri);
	if(!bucket)
	{
		fprintf(stderr, "%s: failed to create S3 bucket object from <%s>\n", short_progname, bucketuri);
		return 1;
	}
	if(verbose)
	{
		fprintf(stderr, "%s: fetching resource '%s' from <s3://%s>\n", short_progname, resource, aws_s3_bucket(bucket));
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
	request = aws_s3_request_create(bucket, resource, "GET");
	if(!request)
	{
		fprintf(stderr, "%s: failed to create S3 request object for <s3://%s/%s>\n", short_progname, aws_s3_bucket(bucket), resource);
		aws_s3_destroy(bucket);
		free(bucketuri);
		return 1;
	}
	ch = aws_request_curl(request);
	curl_easy_setopt(ch, CURLOPT_HEADER, 0);
	curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1);
	if(verbose)
	{
		curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
	}
	status = 0;
	r = 0;
	if(aws_request_perform(request) != CURLE_OK)
	{
		fprintf(stderr, "%s: failed to perform request\n", short_progname);
		r = 1;
	}
	else if(curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
	{
		fprintf(stderr, "%s: failed to obtain HTTP response code\n", short_progname);
		r = 1;
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
		r = 1;		
	}
	else if(status != 200)
	{
		fprintf(stderr, "%s: HTTP request failed with status %d\n", short_progname, (int) status);
		r = 1;
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
	while((c = getopt(argc, argv, "hda:s:e:")) != -1)
	{
		switch(c)
		{
		case 'h':
			usage();
			exit(0);
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
	if(strncmp(argv[0], "s3://", 5))
	{
		fprintf(stderr, "%s: an S3 URL must be provided\n", short_progname);
		usage();
		return -1;
	}
	bucketuri = strdup(argv[0]);
	t = strchr(argv[0] + 5, '/');
	if(!t)
	{
		fprintf(stderr, "%s: no resource path provided in S3 URL\n", short_progname);
		usage();
		return -1;
	}
	*t = 0;
	resource = t + 1;
	return 0;
}

static void
usage(void)
{
	printf("Usage: %s OPTIONS s3://BUCKET/RESOURCE[?params]"
		   "\n"
		   "OPTIONS is one or more of:\n"
		   "  -h                  Print this message and exit\n"
		   "  -d                  Enable debugging output\n"
		   "  -a KEY              Specify access key\n"
		   "  -s KEY              Specify secret key\n"
		   "  -e HOSTNAME         Specify alternative S3 endpoint\n",
		   short_progname);
}

static void
logger(int prio, const char *format, va_list ap)
{
	fprintf(stderr, "%s: <%d> ", short_progname, prio);
	vfprintf(stderr, format, ap);
}

