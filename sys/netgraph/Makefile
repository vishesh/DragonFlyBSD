# $Whistle: Makefile,v 1.5 1999/01/24 06:48:37 archie Exp $
# $FreeBSD: src/sys/modules/netgraph/Makefile,v 1.8.2.8 2002/08/20 23:48:15 archie Exp $
# $DragonFly: src/sys/netgraph/Makefile,v 1.6 2007/10/13 10:45:39 sephe Exp $

SUBDIR=	UI \
	async \
	bpf \
	bridge \
	cisco \
	echo \
	eiface \
	etf \
	ether \
	fec \
	frame_relay \
	hole \
	iface \
	ksocket \
	l2tp \
	lmi \
	netgraph \
	one2many \
	ppp \
	pppoe \
	pptpgre \
	rfc1490 \
	socket \
	sync_ar \
	sync_sr \
	tee \
	tty \
	vjc

.if !defined(NO_CRYPT) && exists(${.CURDIR}/../crypto/rc4/rc4.c)
SUBDIR+=	mppc
.endif

.include <bsd.subdir.mk>
