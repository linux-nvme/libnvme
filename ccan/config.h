/* Prepopulated config.h header from libnvme; we'll be building with gcc */
#ifndef CCAN_CONFIG_H
#define CCAN_CONFIG_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Always use GNU extensions. */
#endif
#define CCAN_COMPILER "cc"
#define CCAN_CFLAGS "-g3 -ggdb -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition"

#define HAVE_BSWAP_64 1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P 1
#define HAVE_BYTESWAP_H 1
#define HAVE_ISBLANK 1
#define HAVE_STATEMENT_EXPR 1
#define HAVE_TYPEOF 1

#if __BYTEORDER == __LITTLE_ENDIAN
#define HAVE_LITTLE_ENDIAN 1
#endif

#if __BYTEORDER == __BIG_ENDIAN
#define HAVE_BIG_ENDIAN 1
#endif

#endif /* CCAN_CONFIG_H */
