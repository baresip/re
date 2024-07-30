/**
 * @file test/dd.c Dependency Descriptor (DD) testcode
 *
 * Copyright (C) 2010 - 2023 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_dd.h>
#include "test.h"


#define DEBUG_MODULE "ddtest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int test_dd_mand(void)
{
	struct dd dd = { 0 };
	struct mbuf *mb = mbuf_alloc(512);

	if (!mb)
		return ENOMEM;

	int err = dd_encode(mb, &dd);
	TEST_ERR(err);

	/* Mandatory Descriptor Fields -- 3 bytes only */
	static const uint8_t buf_exp[] = { 0, 0, 0 };

	TEST_MEMCMP(buf_exp, sizeof(buf_exp), mb->buf, mb->end);

	struct dd dd_dec;

	err = dd_decode(&dd_dec, mb->buf, mb->end);
	TEST_ERR(err);

	ASSERT_EQ(0, dd_dec.start_of_frame);
	ASSERT_EQ(0, dd_dec.end_of_frame);
	ASSERT_EQ(0, dd_dec.frame_dependency_template_id);
	ASSERT_EQ(0, dd_dec.frame_number);

	ASSERT_TRUE(!dd_dec.ext);

 out:
	mem_deref(mb);
	return err;
}


/*

80012f800214eaa860414d1410208426


"startOfFrame":true,
"endOfFrame":false,
"frameDependencyTemplateId":0,
"frameNumber":303,
"templateStructure":{
	"templateIdOffset":0,
	"templateInfo":{
		"0":{
			"spatialId":0,
			"temporalId":0,
			"dti":[
				"SWITCH",
				"SWITCH",
				"SWITCH"
			],
			"fdiff":[

			],
			"chains":[
				0
			]
		},
		"1":{
			"spatialId":0,
			"temporalId":0,
			"dti":[
				"SWITCH",
				"SWITCH",
				"SWITCH"
			],
			"fdiff":[
				4
			],
			"chains":[
				4
			]
		},
		"2":{
			"spatialId":0,
			"temporalId":1,
			"dti":[
				"NOT_PRESENT",
				"DISCARDABLE",
				"SWITCH"
			],
			"fdiff":[
				2
			],
			"chains":[
				2
			]
		},
		"3":{
			"spatialId":0,
			"temporalId":2,
			"dti":[
				"NOT_PRESENT",
				"NOT_PRESENT",
				"DISCARDABLE"
			],
			"fdiff":[
				1
			],
			"chains":[
				1
			]
		},
		"4":{
			"spatialId":0,
			"temporalId":2,
			"dti":[
				"NOT_PRESENT",
				"NOT_PRESENT",
				"DISCARDABLE"
			],
			"fdiff":[
				1
			],
			"chains":[
				3
			]
		}
	},
	"decodeTargetInfo":{
		"0":{
			"protectedBy":0,
			"spatialId":0,
			"temporalId":0
		},
		"1":{
			"protectedBy":0,
			"spatialId":0,
			"temporalId":1
		},
		"2":{
			"protectedBy":0,
			"spatialId":0,
			"temporalId":2
		}
	},
	"maxSpatialId":0,
	"maxTemporalId":2
}
}


 */
static int test_dd_decode(void)
{
	static const char *str = "80012f800214eaa860414d1410208426";
	struct mbuf *mb = mbuf_alloc(8);
	uint8_t buf[16];
	int err;

	if (!mb)
		return ENOMEM;

	err = str_hex(buf, sizeof(buf), str);
	TEST_ERR(err);

	struct dd dd;

	err = dd_decode(&dd, buf, sizeof(buf));
	TEST_ERR(err);

#if 0
	dd_print(&dd);
#endif

	ASSERT_EQ(1, dd.start_of_frame);
	ASSERT_EQ(0, dd.end_of_frame);
	ASSERT_EQ(0, dd.frame_dependency_template_id);
	ASSERT_EQ(303, dd.frame_number);

	ASSERT_EQ(1, dd.template_dependency_structure_present_flag);
	ASSERT_EQ(0, dd.active_decode_targets_present_flag);
	ASSERT_EQ(0, dd.custom_dtis_flag);
	ASSERT_EQ(0, dd.custom_fdiffs_flag);
	ASSERT_EQ(0, dd.custom_chains_flag);

	ASSERT_EQ(7, dd.active_decode_targets_bitmask);
	ASSERT_EQ(0, dd.template_id_offset);
	ASSERT_EQ(3, dd.dt_cnt);
	ASSERT_EQ(5, dd.template_cnt);
	ASSERT_EQ(0, dd.max_spatial_id);

	ASSERT_EQ(0, dd.template_spatial_id[0]);
	ASSERT_EQ(0, dd.template_spatial_id[1]);
	ASSERT_EQ(0, dd.template_spatial_id[2]);
	ASSERT_EQ(0, dd.template_spatial_id[3]);
	ASSERT_EQ(0, dd.template_spatial_id[4]);

	ASSERT_EQ(0, dd.template_temporal_id[0]);
	ASSERT_EQ(0, dd.template_temporal_id[1]);
	ASSERT_EQ(1, dd.template_temporal_id[2]);
	ASSERT_EQ(2, dd.template_temporal_id[3]);
	ASSERT_EQ(2, dd.template_temporal_id[4]);

	ASSERT_TRUE(!dd.resolutions_present_flag);
	ASSERT_EQ(0, dd.render_count);

	ASSERT_EQ(2, dd.template_dti[0][0]);
	ASSERT_EQ(2, dd.template_dti[0][1]);
	ASSERT_EQ(2, dd.template_dti[0][2]);
	ASSERT_EQ(2, dd.template_dti[1][0]);
	ASSERT_EQ(2, dd.template_dti[1][1]);
	ASSERT_EQ(2, dd.template_dti[1][2]);
	ASSERT_EQ(0, dd.template_dti[2][0]);
	ASSERT_EQ(1, dd.template_dti[2][1]);
	ASSERT_EQ(2, dd.template_dti[2][2]);
	ASSERT_EQ(0, dd.template_dti[3][0]);
	ASSERT_EQ(0, dd.template_dti[3][1]);
	ASSERT_EQ(1, dd.template_dti[3][2]);
	ASSERT_EQ(0, dd.template_dti[4][0]);
	ASSERT_EQ(0, dd.template_dti[4][1]);
	ASSERT_EQ(1, dd.template_dti[4][2]);

	ASSERT_EQ(1, dd.chain_cnt);

	err = dd_encode(mb, &dd);
	TEST_ERR(err);

	TEST_MEMCMP(buf, sizeof(buf), mb->buf, mb->end);

 out:
	mem_deref(mb);
	return err;
}


/*
 * Interop test with Chrome Version 118.0.5993.70
 */
static int test_dd_chrome(void)
{
	static const char *str = "80000180003a40813f80ef80";
	struct mbuf *mb = mbuf_alloc(16);
	uint8_t buf[12];
	int err;

	if (!mb)
		return ENOMEM;

	err = str_hex(buf, sizeof(buf), str);
	TEST_ERR(err);

	struct dd dd;

	err = dd_decode(&dd, buf, sizeof(buf));
	TEST_ERR(err);

#if 0
	dd_print(&dd);
#endif

	ASSERT_EQ(1, dd.start_of_frame);
	ASSERT_EQ(0, dd.end_of_frame);
	ASSERT_EQ(0, dd.frame_dependency_template_id);
	ASSERT_EQ(1, dd.frame_number);

	ASSERT_EQ(1, dd.template_dependency_structure_present_flag);
	ASSERT_EQ(0, dd.active_decode_targets_present_flag);
	ASSERT_EQ(0, dd.custom_dtis_flag);
	ASSERT_EQ(0, dd.custom_fdiffs_flag);
	ASSERT_EQ(0, dd.custom_chains_flag);

	ASSERT_EQ(1, dd.active_decode_targets_bitmask);
	ASSERT_EQ(0, dd.template_id_offset);
	ASSERT_EQ(1, dd.dt_cnt);
	ASSERT_EQ(2, dd.template_cnt);
	ASSERT_EQ(0, dd.max_spatial_id);

	ASSERT_EQ(0, dd.template_spatial_id[0]);
	ASSERT_EQ(0, dd.template_spatial_id[1]);

	ASSERT_EQ(0, dd.template_temporal_id[0]);
	ASSERT_EQ(0, dd.template_temporal_id[1]);

	ASSERT_TRUE(dd.resolutions_present_flag);
	ASSERT_EQ(1, dd.render_count);
	ASSERT_EQ(639, dd.max_render_width_minus_1[0]);
	ASSERT_EQ(479, dd.max_render_height_minus_1[0]);

	ASSERT_EQ(2, dd.template_dti[0][0]);
	ASSERT_EQ(2, dd.template_dti[1][0]);

	ASSERT_EQ(0, dd.chain_cnt);

	err = dd_encode(mb, &dd);
	TEST_ERR(err);

	TEST_MEMCMP(buf, sizeof(buf), mb->buf, mb->end);

 out:
	mem_deref(mb);
	return err;
}


int test_dd(void)
{
	int err;

	err = test_dd_mand();
	if (err)
		return err;

	err = test_dd_decode();
	if (err)
		return err;

	err = test_dd_chrome();
	if (err)
		return err;

	return 0;
}
