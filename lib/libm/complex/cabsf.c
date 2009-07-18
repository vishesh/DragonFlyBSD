/* $NetBSD: cabsf.c,v 1.1 2007/08/20 16:01:30 drochner Exp $ */

/*
 * Written by Matthias Drochner <drochner@NetBSD.org>.
 * Public domain.
 */

#include <complex.h>
#include <math.h>
#include "../src/math_private.h"

float
cabsf(float complex z)
{

	return hypotf(crealf(z), cimagf(z));
}
