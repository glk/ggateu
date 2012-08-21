# $FreeBSD$

.PATH: ${.CURDIR}/../shared

WARNS?= 6

PROG=	ggateu
MAN=	ggateu.8
SRCS=	ggateu.c ggate.c salsa20.c

CFLAGS+= -DLIBGEOM
CFLAGS+= -I${.CURDIR}/../shared

DPADD=	${LIBGEOM} ${LIBSBUF} ${LIBBSDXML} ${LIBUTIL}
LDADD=	-lgeom -lsbuf -lbsdxml -lutil

.include <bsd.prog.mk>
