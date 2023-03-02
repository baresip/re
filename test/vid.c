/**
 * @file vid.c Video Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "vid"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static const enum vidfmt fmtv[VID_FMT_N] = {
	VID_FMT_YUV420P,
	VID_FMT_YUYV422,
	VID_FMT_UYVY422,
	VID_FMT_RGB32,
	VID_FMT_ARGB,
	VID_FMT_NV12,
	VID_FMT_NV21,
	VID_FMT_YUV444P,
	VID_FMT_YUV422P,
};


static int test_vidsz_cmp(void)
{
	struct vidsz a = {64, 64}, b = {64, 64}, c = {32, 32};
	int err = 0;

	TEST_ASSERT(!vidsz_cmp(NULL, NULL));
	TEST_ASSERT( vidsz_cmp(&a, &a));
	TEST_ASSERT( vidsz_cmp(&a, &b));
	TEST_ASSERT(!vidsz_cmp(&a, &c));

 out:
	return err;
}


static int test_vidrect_cmp(void)
{
	struct vidrect a = {10, 10, 30, 30};
	struct vidrect b = {10, 10, 30, 30};
	struct vidrect c = {10, 10, 40, 40};
	struct vidrect d = {20, 20, 30, 30};
	int err = 0;

	TEST_ASSERT(!vidrect_cmp(NULL, NULL));
	TEST_ASSERT( vidrect_cmp(&a, &a));
	TEST_ASSERT( vidrect_cmp(&a, &b));
	TEST_ASSERT(!vidrect_cmp(&a, &c));
	TEST_ASSERT(!vidrect_cmp(&a, &d));

 out:
	return err;
}


static int test_vidframe_size(void)
{
	static const struct vidsz vidsz = {32, 32};
	size_t i;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(fmtv); i++) {

		size_t sz = vidframe_size(fmtv[i], &vidsz);

		if (sz == 0) {
			DEBUG_WARNING("unexpected zero size for format %s\n",
				      vidfmt_name(fmtv[i]));
			return EINVAL;
		}

		const char *name = vidfmt_name(fmtv[i]);
		ASSERT_TRUE(str_isset(name));
	}

 out:
	return err;
}


static int test_vidframe_alloc(void)
{
	static const struct vidsz vidsz = {32, 32};
	struct vidframe *vf = NULL;
	size_t i;
	int err = ENOENT;

	for (i=0; i<RE_ARRAY_SIZE(fmtv); i++) {

		err = vidframe_alloc(&vf, fmtv[i], &vidsz);
		if (err)
			break;

		TEST_ASSERT(vidframe_isvalid(vf));

		TEST_NOT_EQUALS(0, vf->linesize[0]);
		TEST_ASSERT(vidsz_cmp(&vidsz, &vf->size));
		TEST_EQUALS(fmtv[i], vf->fmt);

		vf = mem_deref(vf);
	}

 out:
	mem_deref(vf);
	return err;
}


/*
 * Create one RGB32 pixel in native endianess
 */
#define RGB32(r, g, b)  (r)<<16 | (g)<<8 | (b)


/*
 * Test a RGB32 Video-frame with 2 x 2 pixels and 3 RGB pixel
 *
 *    .--+----
 *    |RG|
 *    |B |
 *    +--+----
 *    |
 *    |
 */
static int test_vidframe_rgb32_2x2_red(void)
{
	struct vidframe vf;
	struct vidsz sz = {2, 2};
	uint8_t buf[2*4 + 2*4];
	const uint32_t pix[2][2] = {

		{ RGB32(255U, 0, 0), RGB32(0, 255U, 0) },
		{ RGB32(0, 0, 255U), RGB32(0,    0, 0) }
	};
	int err = 0;

	memset(buf, 0, sizeof(buf));
	vidframe_init_buf(&vf, VID_FMT_RGB32, &sz, buf);

	TEST_EQUALS(buf,  vf.data[0]);
	TEST_EQUALS(NULL, vf.data[1]);
	TEST_EQUALS(NULL, vf.data[2]);
	TEST_EQUALS(NULL, vf.data[3]);

	TEST_EQUALS(8, vf.linesize[0]);
	TEST_EQUALS(0, vf.linesize[1]);
	TEST_EQUALS(0, vf.linesize[2]);
	TEST_EQUALS(0, vf.linesize[3]);

	TEST_EQUALS(2, vf.size.w);
	TEST_EQUALS(2, vf.size.h);

	TEST_EQUALS(VID_FMT_RGB32, vf.fmt);

	vidframe_draw_point(&vf, 0, 0, 255,   0,   0);
	vidframe_draw_point(&vf, 1, 0,   0, 255,   0);
	vidframe_draw_point(&vf, 0, 1,   0,   0, 255);
	vidframe_draw_point(&vf, 1, 1,   0,   0,   0);

	TEST_MEMCMP(pix[0], sizeof(pix[0]), vf.data[0], 8);
	TEST_MEMCMP(pix[1], sizeof(pix[1]), vf.data[0] + vf.linesize[0], 8);

 out:
	return err;
}


static int test_vidframe_yuv_2x2_white(enum vidfmt fmt, unsigned chroma)
{
	struct vidframe *vf;
	struct vidsz sz = {2, 2};
	const uint8_t ypix[4] = {235, 235, 235, 235};
	const uint8_t uvpix[4] = {128, 128, 128, 128};
	const unsigned chroma_sq = chroma * chroma;
	int err;

	err = vidframe_alloc(&vf, fmt, &sz);
	if (err)
		return err;

	vidframe_fill(vf, 255, 255, 255);

	TEST_NOT_EQUALS(NULL, vf->data[0]);
	TEST_NOT_EQUALS(NULL, vf->data[1]);
	TEST_NOT_EQUALS(NULL, vf->data[2]);
	TEST_EQUALS(NULL, vf->data[3]);

	TEST_EQUALS(2, vf->linesize[0]);
	TEST_EQUALS(chroma, vf->linesize[1]);
	TEST_EQUALS(chroma, vf->linesize[2]);
	TEST_EQUALS(0, vf->linesize[3]);

	TEST_EQUALS(2, vf->size.w);
	TEST_EQUALS(2, vf->size.h);

	TEST_EQUALS(fmt, vf->fmt);

	TEST_ASSERT(chroma_sq <= sizeof(uvpix));
	TEST_MEMCMP(ypix, sizeof(ypix), vf->data[0], 4);
	TEST_MEMCMP(uvpix, chroma_sq, vf->data[1], chroma_sq);
	TEST_MEMCMP(uvpix, chroma_sq, vf->data[2], chroma_sq);

 out:
	mem_deref(vf);

	return err;
}


static int test_vid_draw(void)
{
	static const struct vidsz vidsz = {320, 240};
	struct vidframe *vf = NULL, *vf2 = NULL;
	int err = 0;

	static const enum vidfmt drawfmtv[] = {
		VID_FMT_YUV420P,
		VID_FMT_NV12,
		VID_FMT_NV21,
		VID_FMT_YUV444P,
		VID_FMT_YUV422P,
	};

	for (size_t i=0; i<RE_ARRAY_SIZE(drawfmtv); i++) {

		err  = vidframe_alloc(&vf,  drawfmtv[i], &vidsz);
		err |= vidframe_alloc(&vf2, drawfmtv[i], &vidsz);
		if (err)
			break;

		if (vf->fmt == VID_FMT_YUV422P) {

			ASSERT_EQ(320, vf->linesize[0]);
			ASSERT_EQ(160, vf->linesize[1]);
			ASSERT_EQ(160, vf->linesize[2]);
			ASSERT_EQ(  0, vf->linesize[3]);
		}

		for (unsigned x=0; x<vidsz.w; x++)
			for (unsigned y=0; y<vidsz.h; y++)
				vidframe_draw_point(vf, x, y, 127, 127, 127);

		vidframe_fill(vf, 255, 255, 255);

		vidframe_copy(vf2, vf);

		vf2 = mem_deref(vf2);
		vf  = mem_deref(vf);
	}

 out:
	mem_deref(vf2);
	mem_deref(vf);

	return err;
}


int test_vid(void)
{
	int err;

	err = test_vidsz_cmp();
	TEST_ERR(err);

	err = test_vidrect_cmp();
	TEST_ERR(err);

	err = test_vidframe_size();
	TEST_ERR(err);

	err = test_vidframe_alloc();
	TEST_ERR(err);

	err = test_vidframe_rgb32_2x2_red();
	TEST_ERR(err);

	err = test_vidframe_yuv_2x2_white(VID_FMT_YUV420P, 1);
	TEST_ERR(err);

	err = test_vidframe_yuv_2x2_white(VID_FMT_YUV444P, 2);
	TEST_ERR(err);

	err = test_vid_draw();
	TEST_ERR(err);

out:
	return err;
}
