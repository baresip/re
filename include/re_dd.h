/**
 * @file re_dd.h Dependency Descriptor (DD)
 *
 * Copyright (C) 2010 - 2023 Alfred E. Heggestad
 */


/*
 * Put bits wrapper (XXX: move to common place)
 */

struct putbit {
	struct mbuf *mb;
	size_t bit_pos;
};

void putbit_init(struct putbit *pb, struct mbuf *mb);
int  putbit_one(struct putbit *pb, unsigned bit);
int  putbit_write(struct putbit *pb, unsigned count, unsigned val);
int  putbit_write_ns(struct putbit *pb, unsigned n, unsigned v);


/*
 * Dependency Descriptor (DD)
 *
 * DT:  Decode Target
 * DTI: Decode Target Indication
 * SID: Spatial ID
 * TID: Temporal ID
 */

/* Constants. */
enum {
	DD_MAX_SPATIAL_IDS   =   4u,
	DD_MAX_TEMPORAL_IDS  =   4u,
	DD_MAX_TEMPLATES     =   8u,
	DD_MAX_FDIFFS        =  16u,
	DD_MAX_DECODE_TARGETS=  16u,
	DD_MAX_CHAINS        =  32u,
};


/* Decode Target Indication (DTI) */
enum dd_dti {
	DD_DTI_NOT_PRESENT = 0,
	DD_DTI_DISCARDABLE = 1,
	DD_DTI_SWITCH      = 2,
	DD_DTI_REQUIRED    = 3,
};

enum dd_next_layer_idc {
	DD_SAME_LAYER          = 0,
	DD_NEXT_TEMPORAL_LAYER = 1,
	DD_NEXT_SPATIAL_LAYER  = 2,
	DD_NO_MORE_TEMPLATES   = 3,
};

/*
 * https://aomediacodec.github.io/av1-rtp-spec/
 *     #dependency-descriptor-rtp-header-extension
 */
struct dd {

	/* Mandatory Descriptor Fields */
	unsigned start_of_frame:1;
	unsigned end_of_frame:1;
	unsigned frame_dependency_template_id:6;
	uint16_t frame_number;

	bool ext;

	unsigned template_dependency_structure_present_flag:1;
	unsigned active_decode_targets_present_flag:1;
	unsigned custom_dtis_flag:1;
	unsigned custom_fdiffs_flag:1;
	unsigned custom_chains_flag:1;

	unsigned active_decode_targets_bitmask;
	unsigned template_id_offset:6;
	uint8_t dt_cnt;
	uint8_t template_cnt;
	uint8_t max_spatial_id;

	uint8_t template_spatial_id[DD_MAX_TEMPLATES];
	uint8_t template_temporal_id[DD_MAX_TEMPLATES];

	/* render_resolutions */
	bool resolutions_present_flag;
	uint16_t max_render_width_minus_1[DD_MAX_SPATIAL_IDS];
	uint16_t max_render_height_minus_1[DD_MAX_SPATIAL_IDS];
	uint8_t render_count;

	/* type: enum dd_dti */
	uint8_t template_dti[DD_MAX_TEMPLATES][DD_MAX_DECODE_TARGETS];

	/* template fdiffs */
	uint8_t template_fdiff[DD_MAX_TEMPLATES][DD_MAX_FDIFFS];
	uint8_t template_fdiff_cnt[DD_MAX_TEMPLATES];

	/* template chains */
	uint8_t decode_target_protected_by[DD_MAX_DECODE_TARGETS];
	uint8_t template_chain_fdiff[DD_MAX_TEMPLATES][DD_MAX_CHAINS];
	uint8_t chain_cnt;
};

int  dd_encode(struct mbuf *mb, const struct dd *dd);
int  dd_decode(struct dd *dd, const uint8_t *buf, size_t sz);
void dd_print(const struct dd *dd);
