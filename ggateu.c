/*-
 * Copyright (c) 2004 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * Copyright (c) 2012 Gleb Kurtsou <gleb@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/bio.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syslog.h>

#include <geom/gate/g_gate.h>
#include "ggate.h"
#include "salsa20.h"


enum { UNSET, CREATE, DESTROY, LIST, RESCUE, CAT } action = UNSET;

static const char *rpath = NULL;
static const char *wpath = NULL;
static int unit = G_GATE_UNIT_AUTO;
static unsigned flags = 0;
static int force = 0;
static unsigned sectorsize = 0;
static unsigned timeout = G_GATE_TIMEOUT;

static char mangle_key[SALSA20_MAXKEYSIZE / 8] = "ggateu";
static const uint8_t mangle_iv[SALSA20_IVSIZE / 8] = { };
static salsa20_ctx mangle_ctx;

static void
usage(void)
{

	fprintf(stderr, "usage: %s create [-v] [-s sectorsize] [-t timeout] "
	    "[-i iv] [-u unit] -r read-provider -w write-provider\n",
	    getprogname());
	fprintf(stderr, "       %s rescue [-v] <-u unit> "
	    "[-i iv] [-u unit] -r read-provider -w write-provider\n",
	    getprogname());
	fprintf(stderr, "       %s destroy [-f] <-u unit>\n", getprogname());
	fprintf(stderr, "       %s list [-v] [-u unit]\n", getprogname());
	fprintf(stderr, "       %s cat [-s sectorsize] "
	    "[-i iv] [-r read-provider] -w write-provider\n",
	    getprogname());
	exit(EXIT_FAILURE);
}

static int
buf_is_zero(const void *buf, size_t len)
{
	const uint8_t *p, *e;

	p = buf;
	e = p + len;
	if (__predict_false(((uintptr_t)p & 3) != 0))
		switch ((uintptr_t)p & 3) {
		case 3:
			if (*(p++) != 0)
				return 0;
		case 2:
			if (*(p++) != 0)
				return 0;
		case 1:
			if (*(p++) != 0)
				return 0;
		}
	for (; p + 4 <= e; p += 4)
		if (*(const int32_t *)(const void *)p != 0)
			return 0;
	if (__predict_false(p != e))
		switch ((uintptr_t)e - (uintptr_t)p) {
		case 3:
			if (*(p++) != 0)
				return 0;
		case 2:
			if (*(p++) != 0)
				return 0;
		case 1:
			if (*(p++) != 0)
				return 0;
		}

	return 1;
}

static void
buf_mangle(void *buf, size_t len, uint64_t offset)
{
	salsa20_ivsetup(&mangle_ctx, mangle_iv, offset);
	salsa20_crypt(&mangle_ctx, buf, buf, len);
}

static void
g_gateu_serve(int rfd, int wfd)
{
	struct g_gate_ctl_io ggio;
	size_t bsize;

	if (g_gate_verbose == 0) {
		if (daemon(0, 0) == -1) {
			g_gate_destroy(unit, 1);
			err(EXIT_FAILURE, "Cannot daemonize");
		}
	}
	g_gate_log(LOG_DEBUG, "Worker created: %u.", getpid());
	ggio.gctl_version = G_GATE_VERSION;
	ggio.gctl_unit = unit;
	bsize = sectorsize;
	ggio.gctl_data = malloc(bsize);
	for (;;) {
		int error;
once_again:
		ggio.gctl_length = bsize;
		ggio.gctl_error = 0;
		g_gate_ioctl(G_GATE_CMD_START, &ggio);
		error = ggio.gctl_error;
		switch (error) {
		case 0:
			break;
		case ECANCELED:
			/* Exit gracefully. */
			free(ggio.gctl_data);
			g_gate_close_device();
			close(rfd);
			close(wfd);
			exit(EXIT_SUCCESS);
		case ENOMEM:
			/* Buffer too small. */
			assert(ggio.gctl_cmd == BIO_DELETE ||
			    ggio.gctl_cmd == BIO_WRITE);
			ggio.gctl_data = realloc(ggio.gctl_data,
			    ggio.gctl_length);
			if (ggio.gctl_data != NULL) {
				bsize = ggio.gctl_length;
				goto once_again;
			}
			/* FALLTHROUGH */
		case ENXIO:
		default:
			g_gate_xlog("ioctl(/dev/%s): %s.", G_GATE_CTL_NAME,
			    strerror(error));
		}

		error = 0;
		switch (ggio.gctl_cmd) {
		case BIO_READ:
			if ((size_t)ggio.gctl_length > bsize) {
				ggio.gctl_data = realloc(ggio.gctl_data,
				    ggio.gctl_length);
				if (ggio.gctl_data != NULL)
					bsize = ggio.gctl_length;
				else {
					error = ENOMEM;
					break;
				}
			}
			if (pread(wfd, ggio.gctl_data, ggio.gctl_length,
			    ggio.gctl_offset) == -1) {
				error = errno;
				break;
			}
			if (!buf_is_zero(ggio.gctl_data, ggio.gctl_length)) {
				buf_mangle(ggio.gctl_data, ggio.gctl_length,
				    ggio.gctl_offset);
			} else {
				if (pread(rfd, ggio.gctl_data, ggio.gctl_length,
				    ggio.gctl_offset) == -1) {
					error = errno;
					break;
				}
			}
			break;
		case BIO_DELETE:
			memset(ggio.gctl_data, 0, ggio.gctl_length);
			if (pwrite(wfd, ggio.gctl_data, ggio.gctl_length,
			    ggio.gctl_offset) == -1) {
				error = errno;
			}
			break;
		case BIO_WRITE:
			buf_mangle(ggio.gctl_data, ggio.gctl_length,
			    ggio.gctl_offset);
			if (pwrite(wfd, ggio.gctl_data, ggio.gctl_length,
			    ggio.gctl_offset) == -1) {
				error = errno;
			}
			break;
		default:
			error = EOPNOTSUPP;
		}

		ggio.gctl_error = error;
		g_gate_ioctl(G_GATE_CMD_DONE, &ggio);
	}
}

static void
g_gateu_create(void)
{
	struct g_gate_ctl_create ggioc;
	off_t mediasize, wmediasize;
	int rfd, wfd;

	rfd = open(rpath, O_RDONLY | O_DIRECT | O_FSYNC);
	if (rfd == -1)
		err(EXIT_FAILURE, "Cannot open %s", rpath);
	wfd = open(wpath, O_RDWR | O_DIRECT | O_FSYNC);
	if (rfd == -1)
		err(EXIT_FAILURE, "Cannot open %s", wpath);
	mediasize = g_gate_mediasize(rfd);
	wmediasize = g_gate_mediasize(wfd);
	if (wmediasize < mediasize)
		errx(EXIT_FAILURE, "Invalid media sizes, "
		    "upper level provider too small: %ju %ju",
		    (uintmax_t)mediasize, (uintmax_t)wmediasize);
	else if (wmediasize != mediasize)
		g_gate_log(LOG_DEBUG, "Provider media sizes mismatch: %ju %ju",
		    (uintmax_t)mediasize, (uintmax_t)wmediasize);

	ggioc.gctl_version = G_GATE_VERSION;
	ggioc.gctl_unit = unit;
	ggioc.gctl_mediasize = mediasize;
	if (sectorsize == 0)
		sectorsize = g_gate_sectorsize(rfd);
	ggioc.gctl_sectorsize = sectorsize;
	ggioc.gctl_timeout = timeout;
	ggioc.gctl_flags = flags;
	ggioc.gctl_maxcount = 0;
	snprintf(ggioc.gctl_info, sizeof(ggioc.gctl_info), "%s %s",
	    rpath, wpath);
	g_gate_ioctl(G_GATE_CMD_CREATE, &ggioc);
	if (unit == -1)
		printf("%s%u\n", G_GATE_PROVIDER_NAME, ggioc.gctl_unit);
	unit = ggioc.gctl_unit;
	g_gateu_serve(rfd, wfd);
}

static void
g_gateu_rescue(void)
{
	struct g_gate_ctl_cancel ggioc;
	int rfd, wfd;

	rfd = open(rpath, O_RDONLY | O_DIRECT | O_FSYNC);
	if (rfd == -1)
		err(EXIT_FAILURE, "Cannot open %s", rpath);
	wfd = open(wpath, O_RDWR | O_DIRECT | O_FSYNC);
	if (rfd == -1)
		err(EXIT_FAILURE, "Cannot open %s", wpath);
	if (sectorsize == 0)
		sectorsize = g_gate_sectorsize(rfd != -1 ? rfd : wfd);

	ggioc.gctl_version = G_GATE_VERSION;
	ggioc.gctl_unit = unit;
	ggioc.gctl_seq = 0;
	g_gate_ioctl(G_GATE_CMD_CANCEL, &ggioc);

	g_gateu_serve(rfd, wfd);
}

static void
g_gateu_cat(void)
{
	char *buf;
	off_t off, mediasize;
	int rfd, wfd;

	if (rpath != NULL) {
		rfd = open(rpath, O_RDONLY | O_DIRECT | O_FSYNC);
		if (rfd == -1)
			err(EXIT_FAILURE, "Cannot open %s", rpath);
	} else
		rfd = -1;
	wfd = open(wpath, O_RDONLY | O_DIRECT | O_FSYNC);
	if (rfd == -1)
		err(EXIT_FAILURE, "Cannot open %s", wpath);

	if (sectorsize == 0)
		sectorsize = g_gate_sectorsize(rfd != -1 ? rfd : wfd);
	mediasize = g_gate_mediasize(rfd != -1 ? rfd : wfd);
	if (mediasize % sectorsize != 0)
		errx(EXIT_FAILURE, "Invalid media size %jd for %d bytes sector",
		    (uintmax_t)mediasize, sectorsize);

	buf = malloc(sectorsize);
	for (off = 0; off < mediasize; off += sectorsize) {
		if (pread(wfd, buf, sectorsize, off) == -1)
			err(EXIT_FAILURE, "read failed: %s", wpath);
		if (buf_is_zero(buf, sectorsize)) {
			if (rfd != -1 && pread(rfd, buf, sectorsize, off) == -1)
				err(EXIT_FAILURE, "read failed: %s", rpath);
		} else
			buf_mangle(buf, sectorsize, off);
		if (write(STDOUT_FILENO, buf, sectorsize) == -1)
			err(EXIT_FAILURE, "write failed");
	}
	free(buf);
}

int
main(int argc, char *argv[])
{

	if (argc < 2)
		usage();
	if (strcasecmp(argv[1], "create") == 0)
		action = CREATE;
	else if (strcasecmp(argv[1], "rescue") == 0)
		action = RESCUE;
	else if (strcasecmp(argv[1], "destroy") == 0)
		action = DESTROY;
	else if (strcasecmp(argv[1], "list") == 0)
		action = LIST;
	else if (strcasecmp(argv[1], "cat") == 0)
		action = CAT;
	else
		usage();
	argc -= 1;
	argv += 1;
	for (;;) {
		int ch;

		ch = getopt(argc, argv, "fi:r:s:t:u:vw:");
		if (ch == -1)
			break;
		switch (ch) {
		case 'f':
			if (action != DESTROY)
				usage();
			force = 1;
			break;
		case 'i':
			if (strlen(optarg) > sizeof(mangle_key))
				errx(EXIT_FAILURE, "Invalid IV size, %zd bytes max.",
				    sizeof(mangle_key));
			memset(mangle_key, 0, sizeof(mangle_key));
			strncpy(mangle_key, optarg, sizeof(mangle_key));
			break;
		case 's':
			if (action != CREATE)
				usage();
			errno = 0;
			sectorsize = strtoul(optarg, NULL, 10);
			if (sectorsize == 0 && errno != 0)
				errx(EXIT_FAILURE, "Invalid sectorsize.");
			break;
		case 't':
			if (action != CREATE)
				usage();
			errno = 0;
			timeout = strtoul(optarg, NULL, 10);
			if (timeout == 0 && errno != 0)
				errx(EXIT_FAILURE, "Invalid timeout.");
			break;
		case 'u':
			errno = 0;
			unit = strtol(optarg, NULL, 10);
			if (unit == 0 && errno != 0)
				errx(EXIT_FAILURE, "Invalid unit number.");
			break;
		case 'v':
			if (action == DESTROY)
				usage();
			g_gate_verbose++;
			break;
		case 'r':
			rpath = optarg;
			if (rpath[0] == '\0')
				usage();
			break;
		case 'w':
			wpath = optarg;
			if (wpath[0] == '\0')
				usage();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	salsa20_keysetup(&mangle_ctx, mangle_key, sizeof(mangle_key) * 8);

	switch (action) {
	case CREATE:
		if (rpath == NULL || wpath == NULL)
			usage();
		g_gate_load_module();
		g_gate_open_device();
		g_gateu_create();
		break;
	case RESCUE:
		if (rpath == NULL || wpath == NULL)
			usage();
		if (unit == -1) {
			fprintf(stderr, "Required unit number.\n");
			usage();
		}
		g_gate_open_device();
		g_gateu_rescue();
		break;
	case DESTROY:
		if (unit == -1) {
			fprintf(stderr, "Required unit number.\n");
			usage();
		}
		g_gate_verbose = 1;
		g_gate_open_device();
		g_gate_destroy(unit, force);
		break;
	case LIST:
		g_gate_list(unit, g_gate_verbose);
		break;
	case CAT:
		if (wpath == NULL)
			usage();
		g_gateu_cat();
		break;
	case UNSET:
	default:
		usage();
	}
	g_gate_close_device();
	exit(EXIT_SUCCESS);
}
