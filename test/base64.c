// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 * Unit tests for the base64 encoder/decoder.
 */

#include <stdio.h>
#include <string.h>

int base64_encode(const unsigned char *src, int srclen, char *dst);
int base64_decode(const char *src, int srclen, unsigned char *dst);

struct vector {
	const char *b64;
	const char *plain; /* NULL: decode must fail */
};

/* RFC 4648 test vectors plus malformed padding placements */
static struct vector vectors[] = {
	{ "", "" },
	{ "Zg==", "f" },
	{ "Zm8=", "fo" },
	{ "Zm9v", "foo" },
	{ "Zm9vYg==", "foob" },
	{ "Zm9vYmE=", "fooba" },
	{ "Zm9vYmFy", "foobar" },
	/* non-zero bits hidden by padding */
	{ "Zh==", NULL },
	{ "QUJ=", NULL },
	/* padding only terminates a 4-char quantum, at most twice */
	{ "Zg=", NULL },
	{ "Z===", NULL },
	{ "Zm9vYg=", NULL },
	{ "Zg==Zg==", NULL },
	{ "=Zm9", NULL },
	{ "Zm=g", NULL },
	/* missing padding */
	{ "Zg", NULL },
	{ "Zm9", NULL },
	/* not in the alphabet */
	{ "Zm9v?", NULL },
};

static int nfail;

static void run_vectors(void)
{
	unsigned char plain[64];
	char b64[64];
	unsigned int i;
	int rc;

	for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		struct vector *v = &vectors[i];

		rc = base64_decode(v->b64, strlen(v->b64), plain);
		if (!v->plain) {
			if (rc >= 0) {
				printf("FAIL: '%s' decoded, expected rejection\n", v->b64);
				nfail++;
			}
			continue;
		}
		if (rc != (int)strlen(v->plain) ||
		    memcmp(plain, v->plain, strlen(v->plain))) {
			printf("FAIL: '%s' did not decode to '%s'\n", v->b64, v->plain);
			nfail++;
			continue;
		}
		rc = base64_encode((const unsigned char *)v->plain,
				   strlen(v->plain), b64);
		if (rc != (int)strlen(v->b64) ||
		    memcmp(b64, v->b64, strlen(v->b64))) {
			printf("FAIL: '%s' did not round-trip to '%s'\n",
			       v->plain, v->b64);
			nfail++;
		}
	}
}

/* exercise every quantum/resize boundary with a round trip */
static void run_roundtrips(void)
{
	unsigned char data[253], back[256];
	char enc[344];
	int i, e, d;

	for (i = 0; i < (int)sizeof(data); i++)
		data[i] = (unsigned char)i;

	for (i = 0; i <= (int)sizeof(data); i++) {
		e = base64_encode(data, i, enc);
		d = base64_decode(enc, e, back);
		if (d != i || memcmp(data, back, i)) {
			printf("FAIL: round trip of %d bytes\n", i);
			nfail++;
		}
	}
}

int main(void)
{
	run_vectors();
	run_roundtrips();

	if (nfail) {
		printf("%d test(s) failed\n", nfail);
		return 1;
	}
	printf("all tests passed\n");
	return 0;
}
