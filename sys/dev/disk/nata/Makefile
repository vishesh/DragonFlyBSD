SUBDIR=		nata natacard natadisk nataisa natapci natapicd natapifd \
		natapist natapicam
#SUBDIR+=	nataraid

.if !defined(WANT_USB4BSD)
SUBDIR+=	natausb
.endif

.include <bsd.subdir.mk>
