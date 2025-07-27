/**
 * @file dd.c Dependency Descriptor (DD) -- decoder
 *
 * Copyright (C) 2023 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_dd.h>


#define dd_f(n) get_bits(gb, (n))


static const char *dti_name(enum dd_dti dti)
{
	switch (dti) {

	case DD_DTI_NOT_PRESENT:  return "NOT_PRESENT";
	case DD_DTI_DISCARDABLE:  return "DISCARDABLE";
	case DD_DTI_SWITCH:       return "SWITCH";
	case DD_DTI_REQUIRED:     return "REQUIRED";
	}

	return "???";
}


#if 0
static const char *next_layer_name(enum dd_next_layer_idc idc)
{
	switch (idc) {

	case DD_SAME_LAYER:          return "Same";
	case DD_NEXT_TEMPORAL_LAYER: return "Temporal";
	case DD_NEXT_SPATIAL_LAYER:  return "Spatial";
	case DD_NO_MORE_TEMPLATES:   return "None";
	}

	return "???";
}
#endif


static int mandatory_descriptor_fields(struct dd *dd, struct getbit *gb)
{
	if (getbit_get_left(gb) < 24)
		return EBADMSG;

	dd->start_of_frame               = dd_f(1);
	dd->end_of_frame                 = dd_f(1);
	dd->frame_dependency_template_id = dd_f(6);
	dd->frame_number                 = dd_f(16);

	return 0;
}


/*
 * 0  next template has the same spatial ID and temporal ID as current template
 *
 * 1  next template has the same spatial ID and temporal ID plus 1 compared
 *    with the current Frame dependency template.
 *
 * 2  next Frame dependency template has temporal ID equal to 0 and
 *    spatial ID plus 1 compared with the current Frame dependency template.
 *
 * 3  No more Frame dependency templates are present in the
 *    Frame dependency structure.
 */
static int template_layers(struct dd *dd, struct getbit *gb)
{
	uint8_t temporalId = 0;
	uint8_t spatialId = 0;
	uint8_t TemplateCnt = 0;
	uint8_t MaxTemporalId = 0;
	uint8_t next_layer_idc = DD_SAME_LAYER;

	do {
		if (TemplateCnt >= DD_MAX_TEMPLATES)
			return EOVERFLOW;

		dd->template_spatial_id[TemplateCnt] = spatialId;
		dd->template_temporal_id[TemplateCnt] = temporalId;

		++TemplateCnt;

		if (getbit_get_left(gb) < 2)
			return EBADMSG;

		next_layer_idc = dd_f(2);

		/* next_layer_idc == 0 - same sid and tid */
		if (next_layer_idc == DD_NEXT_TEMPORAL_LAYER) {
			++temporalId;
			if (temporalId > MaxTemporalId) {
				MaxTemporalId = temporalId;
			}
		}
		else if (next_layer_idc == DD_NEXT_SPATIAL_LAYER) {
			temporalId = 0;
			++spatialId;
		}
	}
	while (next_layer_idc != DD_NO_MORE_TEMPLATES);

	dd->max_spatial_id = spatialId;
	dd->template_cnt = TemplateCnt;

	return 0;
}


static int template_dtis(struct dd *dd, struct getbit *gb)
{
	for (uint8_t templateIndex = 0;
	     templateIndex < dd->template_cnt;
	     templateIndex++) {

		if (templateIndex >= DD_MAX_TEMPLATES)
			return EOVERFLOW;

		for (uint8_t dtIndex = 0; dtIndex < dd->dt_cnt; dtIndex++) {

			if (getbit_get_left(gb) < 2)
				return EBADMSG;

			/* See table A.1 below for meaning of DTI values. */
			dd->template_dti[templateIndex][dtIndex] = dd_f(2);
		}
	}

	return 0;
}


static int template_fdiffs(struct dd *dd, struct getbit *gb)
{
	for (uint8_t templateIndex = 0;
	     templateIndex < dd->template_cnt;
	     templateIndex++) {

		uint8_t fdiffCnt = 0;

		if (getbit_get_left(gb) < 1)
			return EBADMSG;

		bool fdiff_follows_flag = dd_f(1);

		while (fdiff_follows_flag) {

			if (getbit_get_left(gb) < 5)
				return EBADMSG;

			uint8_t fdiff_minus_one = dd_f(4);

			uint8_t fdiff = fdiff_minus_one + 1;

			dd->template_fdiff[templateIndex][fdiffCnt] = fdiff;

			++fdiffCnt;
			fdiff_follows_flag = dd_f(1);
		}

		dd->template_fdiff_cnt[templateIndex] = fdiffCnt;
	}

	return 0;
}


static int template_chains(struct dd *dd, struct getbit *gb)
{
	/* todo: check bits left */
	dd->chain_cnt = getbit_read_ns(gb, dd->dt_cnt + 1);

	if (dd->chain_cnt == 0)
		return 0;

	for (uint8_t dtIndex = 0; dtIndex < dd->dt_cnt; dtIndex++) {
		uint8_t v = getbit_read_ns(gb, dd->chain_cnt);
		dd->decode_target_protected_by[dtIndex] = v;
	}

	for (uint8_t templateIndex = 0;
	     templateIndex < dd->template_cnt;
	     templateIndex++) {

		for (uint8_t chainIndex = 0;
		     chainIndex < dd->chain_cnt;
		     chainIndex++) {

			if (getbit_get_left(gb) < 4)
				return EBADMSG;

			dd->template_chain_fdiff[templateIndex][chainIndex] =
				dd_f(4);
		}
	}

	return 0;
}


static int render_resolutions(struct dd *dd, struct getbit *gb)
{
	for (uint8_t spatial_id = 0;
	     spatial_id <= dd->max_spatial_id;
	     spatial_id++) {

		if (getbit_get_left(gb) < 32)
			return EBADMSG;

		dd->max_render_width_minus_1[spatial_id]  = dd_f(16);
		dd->max_render_height_minus_1[spatial_id] = dd_f(16);

		++dd->render_count;
	}

	return 0;
}


static int template_dependency_structure(struct dd *dd, struct getbit *gb)
{
	if (getbit_get_left(gb) < 11)
		return EBADMSG;

	dd->template_id_offset = dd_f(6);
	uint8_t dt_cnt_minus_one = dd_f(5);

	dd->dt_cnt = dt_cnt_minus_one + 1;

	int err = template_layers(dd, gb);
	if (err)
		return err;

	err = template_dtis(dd, gb);
	if (err)
		return err;

	err = template_fdiffs(dd, gb);
	if (err)
		return err;

	template_chains(dd, gb);

	/* note:  decode_target_layers() */

	if (getbit_get_left(gb) < 1)
		return EBADMSG;

	dd->resolutions_present_flag = dd_f(1);
	if (dd->resolutions_present_flag) {
		err = render_resolutions(dd, gb);
		if (err)
			return err;
	}

	return 0;
}


static int extended_descriptor_fields(struct dd *dd, struct getbit *gb)
{
	if (getbit_get_left(gb) < 5)
		return EBADMSG;

	dd->template_dependency_structure_present_flag = dd_f(1);
	dd->active_decode_targets_present_flag = dd_f(1);
	dd->custom_dtis_flag   = dd_f(1);
	dd->custom_fdiffs_flag = dd_f(1);
	dd->custom_chains_flag = dd_f(1);

	if (dd->template_dependency_structure_present_flag) {

		int err = template_dependency_structure(dd, gb);
		if (err)
			return err;

		dd->active_decode_targets_bitmask = (1u << dd->dt_cnt) - 1;
	}

	if (dd->active_decode_targets_present_flag) {

		dd->active_decode_targets_bitmask = dd_f(dd->dt_cnt);
	}

	return 0;
}


static void no_extended_descriptor_fields(struct dd *dd)
{
	dd->custom_dtis_flag   = 0;
	dd->custom_fdiffs_flag = 0;
	dd->custom_chains_flag = 0;
}


int dd_decode(struct dd *dd, const uint8_t *buf, size_t sz)
{
	if (!dd || !buf)
		return EINVAL;

	memset(dd, 0, sizeof(*dd));

	struct getbit gb;

	getbit_init(&gb, buf, sz*8);

	int err = mandatory_descriptor_fields(dd, &gb);
	if (err)
		return err;

	if (sz > 3) {
		err = extended_descriptor_fields(dd, &gb);
		if (err)
			return err;

		dd->ext = true;
	}
	else {
		no_extended_descriptor_fields(dd);
	}

	return 0;
}


void dd_print(const struct dd *dd)
{
	if (!dd)
		return;

	re_printf("~~~~ DD: ~~~~\n");

	re_printf(".... start=%d, end=%d,"
		  " frame_dependency_template_id=%u, frame_number=%u\n",
		  dd->start_of_frame,
		  dd->end_of_frame,
		  dd->frame_dependency_template_id,
		  dd->frame_number);
	re_printf(".... ext: %d\n", dd->ext);

	if (dd->ext) {

		re_printf(".... template_dependency_structure_present:   %u\n",
			  dd->template_dependency_structure_present_flag);
		re_printf(".... active_decode_targets_present_flag:      %u\n",
			  dd->active_decode_targets_present_flag);
		re_printf(".... custom_dtis_flag:                        %u\n",
			  dd->custom_dtis_flag);
		re_printf(".... custom_fdiffs_flag:                      %u\n",
			  dd->custom_fdiffs_flag);
		re_printf(".... custom_chains_flag:                      %u\n",
			  dd->custom_chains_flag);
		re_printf("\n");

		re_printf(".... active_decode_targets_bitmask: 0x%x\n",
			  dd->active_decode_targets_bitmask);
		re_printf(".... template_id_offset:            %u\n",
			  dd->template_id_offset);
		re_printf(".... dt_cnt:                        %u\n",
			  dd->dt_cnt);
		re_printf(".... template_cnt:                  %u\n",
			  dd->template_cnt);
		re_printf(".... max_spatial_id:                %u\n",
			  dd->max_spatial_id);
		re_printf("\n");

		re_printf(".... template spatial/temporal ids:\n");
		for (uint8_t i=0; i<dd->template_cnt; i++) {

			re_printf(".... [%u] spatial=%u temporal=%u\n",
				  i,
				  dd->template_spatial_id[i],
				  dd->template_temporal_id[i]);
		}
		re_printf("\n");

		re_printf(".... resolutions_present_flag: %u\n",
			  dd->resolutions_present_flag);
		re_printf(".... render_count: %u\n", dd->render_count);
		for (uint8_t i = 0; i < dd->render_count; i++) {

			re_printf(".... max_render %u:        %u x %u\n",
				  i,
				  dd->max_render_width_minus_1[i] + 1,
				  dd->max_render_height_minus_1[i] + 1);
		}
		re_printf("\n");

		for (uint8_t i = 0; i < dd->template_cnt; i++) {

			uint8_t fdiffCnt = dd->template_fdiff_cnt[i];

			re_printf(".... [%u] template_fdiff_cnt: %u",
				  i, fdiffCnt);

			for (uint8_t j = 0; j < fdiffCnt; j++) {

				uint8_t fdiff;

				fdiff = dd->template_fdiff[i][j];

				re_printf("  <fdiff=%u>", fdiff);
			}

			re_printf("\n");
		}
		re_printf("\n");

		re_printf(".... chain_cnt:             %u\n", dd->chain_cnt);
		re_printf("\n");

		re_printf(".... template_dti: 2D\n");
		for (uint8_t tix = 0; tix < dd->template_cnt; tix++) {

			for (uint8_t dtix = 0; dtix < dd->dt_cnt; dtix++) {

				uint8_t val = dd->template_dti[tix][dtix];

				re_printf(".... DTI:  [%u][%u] %u %s\n",
					  tix, dtix, val, dti_name(val));
			}
		}
	}

	re_printf("~~~~~~~~~~~~\n");
	re_printf("\n");
}
