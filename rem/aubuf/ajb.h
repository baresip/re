/**
 * @file ajb.h  Adaptive Jitter Buffer interface
 *
 * Copyright (C) 2022 Commend.com - c.spielberger@commend.com
 */

enum ajb_state {
	AJB_GOOD = 0,
	AJB_LOW,
	AJB_HIGH,
};

struct ajb;

struct ajb *ajb_alloc(double silence, size_t wish_sz);
void ajb_reset(struct ajb *ajb);
void ajb_calc(struct ajb *ajb, const struct auframe *af, size_t sampc);
enum ajb_state ajb_get(struct ajb *ajb, struct auframe *af);
int32_t ajb_debug(const struct ajb *ajb);
void ajb_set_ts0(struct ajb *ajb, uint64_t timestamp);
