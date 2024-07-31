/**
 * @file dd_enc.c Dependency Descriptor (DD) -- encoder
 *
 * Copyright (C) 2023 Alfred E. Heggestad
 */

#include <string.h>
#include <re.h>
#include <re_dd.h>


#define DEBUG_MODULE "dd"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int mandatory_descriptor_fields(struct putbit *pb, const struct dd *dd)
{
	int err = 0;

	err |= putbit_one(pb, dd->start_of_frame);
	err |= putbit_one(pb, dd->end_of_frame);
	err |= putbit_write(pb, 6, dd->frame_dependency_template_id);
	err |= putbit_write(pb, 16, dd->frame_number);

	return err;
}


static uint8_t next_layer(const struct dd *dd, unsigned prev, unsigned next)
{
	if (dd->template_spatial_id[next] == dd->template_spatial_id[prev] &&
	    dd->template_temporal_id[next] == dd->template_temporal_id[prev]) {

		return DD_SAME_LAYER;
	}
	else if (dd->template_spatial_id[next] ==
		 dd->template_spatial_id[prev] &&
		 dd->template_temporal_id[next] ==
		 dd->template_temporal_id[prev] + 1) {

		return DD_NEXT_TEMPORAL_LAYER;
	}
	else if (dd->template_spatial_id[next] ==
		 dd->template_spatial_id[prev] + 1 &&
		 dd->template_temporal_id[next] == 0) {

		return DD_NEXT_SPATIAL_LAYER;
	}

	return DD_NO_MORE_TEMPLATES;
}


static int template_layers(struct putbit *pb, const struct dd *dd)
{
	int err = 0;

	for (unsigned i = 1; i < dd->template_cnt; ++i) {

		uint8_t next_layer_idc = next_layer(dd, i - 1, i);
		if (next_layer_idc == DD_NO_MORE_TEMPLATES)
			return EBADMSG;

		err |= putbit_write(pb, 2, next_layer_idc);
	}

	/* end of layers */
	err |= putbit_write(pb, 2, DD_NO_MORE_TEMPLATES);

	return err;
}


static int template_dtis(struct putbit *pb, const struct dd *dd)
{
	for (uint8_t templateIndex = 0;
	     templateIndex < dd->template_cnt;
	     templateIndex++) {

		for (uint8_t dtIndex = 0; dtIndex < dd->dt_cnt; dtIndex++) {

			/* See table A.1 below for meaning of DTI values. */

			uint8_t v = dd->template_dti[templateIndex][dtIndex];

			int err = putbit_write(pb, 2, v);
			if (err)
				return err;
		}
	}

	return 0;
}


static int template_fdiffs(struct putbit *pb, const struct dd *dd)
{
	int err;

	for (uint8_t templateIndex = 0;
	     templateIndex < dd->template_cnt;
	     templateIndex++) {

		uint8_t fdiffCnt = dd->template_fdiff_cnt[templateIndex];

		for (uint8_t j = 0; j < fdiffCnt; j++) {

			uint8_t fdiff;

			fdiff = dd->template_fdiff[templateIndex][j];

			/* fdiff_follows_flag */
			err = putbit_write(pb, 1, true);
			if (err)
				return err;

			err = putbit_write(pb, 4, fdiff - 1);
			if (err)
				return err;
		}

		/* fdiff_follows_flag */
		err = putbit_write(pb, 1, false);
		if (err)
			return err;
	}

	return 0;
}


static int template_chains(struct putbit *pb, const struct dd *dd)
{
	int err = putbit_write_ns(pb, dd->dt_cnt + 1, dd->chain_cnt);
	if (err)
		return err;

	if (dd->chain_cnt == 0)
		return 0;

	for (uint8_t dtIndex = 0; dtIndex < dd->dt_cnt; dtIndex++) {

		uint8_t val = dd->decode_target_protected_by[dtIndex];

		err = putbit_write_ns(pb, dd->chain_cnt, val);
		if (err)
			return err;
	}

	for (uint8_t templateIndex = 0;
	     templateIndex < dd->template_cnt;
	     templateIndex++) {

		for (uint8_t chainIndex = 0;
		     chainIndex < dd->chain_cnt;
		     chainIndex++) {

			uint8_t val;

		       val=dd->template_chain_fdiff[templateIndex][chainIndex];

			err = putbit_write(pb, 4, val);
			if (err)
				return err;
		}
	}

	return 0;
}


static int render_resolutions(struct putbit *pb, const struct dd *dd)
{
	for (uint8_t i=0; i<dd->render_count; i++) {

		putbit_write(pb, 16, dd->max_render_width_minus_1[i]);
		putbit_write(pb, 16, dd->max_render_height_minus_1[i]);
	}

	return 0;
}


static int template_dependency_structure(struct putbit *pb,
					 const struct dd *dd)
{
	int err;

	uint8_t dt_cnt_minus_one = dd->dt_cnt - 1;

	err  = putbit_write(pb, 6, dd->template_id_offset);
	err |= putbit_write(pb, 5, dt_cnt_minus_one);
	if (err)
		return err;

	err = template_layers(pb, dd);
	if (err)
		return err;

	err = template_dtis(pb, dd);
	if (err)
		return err;

	err = template_fdiffs(pb, dd);
	if (err)
		return err;

	err = template_chains(pb, dd);
	if (err)
		return err;

	err = putbit_one(pb, dd->resolutions_present_flag);
	if (err)
		return err;

	if (dd->resolutions_present_flag) {
		render_resolutions(pb, dd);
	}

	/* XXX  decode_target_layers() */

	return 0;
}


static int extended_descriptor_fields(struct putbit *pb, const struct dd *dd)
{
	int err = 0;

	err |= putbit_one(pb, dd->template_dependency_structure_present_flag);
	err |= putbit_one(pb, dd->active_decode_targets_present_flag);
	err |= putbit_one(pb, dd->custom_dtis_flag);
	err |= putbit_one(pb, dd->custom_fdiffs_flag);
	err |= putbit_one(pb, dd->custom_chains_flag);
	if (err)
		return err;

	if (dd->template_dependency_structure_present_flag) {

		err = template_dependency_structure(pb, dd);
		if (err)
			return err;
	}

	if (dd->active_decode_targets_present_flag) {
		DEBUG_WARNING("no active_decode_targets_present_flag\n");
		return ENOTSUP;
	}

	return 0;
}


int dd_encode(struct mbuf *mb, const struct dd *dd)
{
	struct putbit pb;

	if (!mb || !dd)
		return EINVAL;

	putbit_init(&pb, mb);

	int err = mandatory_descriptor_fields(&pb, dd);
	if (err)
		return err;

	if (dd->ext) {
		err = extended_descriptor_fields(&pb, dd);
		if (err)
			return err;
	}

	return 0;
}
