/**
 * @file au/fmt.c  Audio formats
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include <rem_au.h>


/* Number of bytes per sample */
size_t aufmt_sample_size(enum aufmt fmt)
{
	switch (fmt) {

	case AUFMT_S16LE:   return sizeof(int16_t);
	case AUFMT_S32LE:   return sizeof(int32_t);
	case AUFMT_RAW:     return 1;
	case AUFMT_PCMA:    return 1;
	case AUFMT_PCMU:    return 1;
	case AUFMT_FLOAT:   return sizeof(float);
	case AUFMT_S24_3LE: return 3;
	default:            return 0;
	}
}


const char *aufmt_name(enum aufmt fmt)
{
	switch (fmt) {

	case AUFMT_S16LE:   return "S16LE";
	case AUFMT_S32LE:   return "S32LE";
	case AUFMT_PCMA:    return "PCMA";
	case AUFMT_PCMU:    return "PCMU";
	case AUFMT_FLOAT:   return "FLOAT";
	case AUFMT_S24_3LE: return "S24_3LE";
	case AUFMT_RAW:     return "RAW";
	default:            return "???";
	}
}
