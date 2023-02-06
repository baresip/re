/**
 * @file goertzel.c  Goertzel algorithm
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <math.h>
#include <re.h>
#include <rem_goertzel.h>


#define PI 3.14159265358979323846264338327


/**
 * Initialize goertzel state
 *
 * @param g     Goertzel state
 * @param freq  Target frequency
 * @param srate Sample rate
 */
void goertzel_init(struct goertzel *g, double freq, unsigned srate)
{
	g->q1   = 0.0;
	g->q2   = 0.0;
	g->coef = 2.0 * cos(2.0 * PI * (freq/(double)srate));
}


/**
 * Reset goertzel state
 *
 * @param g Goertzel state
 */
void goertzel_reset(struct goertzel *g)
{
	g->q1 = 0.0;
	g->q2 = 0.0;
}


/**
 * Calculate result and reset state
 *
 * @param g Goertzel state
 *
 * @return Result value
 */
double goertzel_result(struct goertzel *g)
{
	double res;

	goertzel_update(g, 0);

	res = g->q1*g->q1 + g->q2*g->q2 - g->q1*g->q2*g->coef;

	goertzel_reset(g);

	return res * 2.0;
}
