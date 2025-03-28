/**
 * @file vidconv.c Video conversion Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rem.h>
#include "test.h"


#define DEBUG_MODULE "vidconv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * http://en.wikipedia.org/wiki/YCbCr
 *
 * ITU-R BT.601 conversion
 *
 * Digital YCbCr can derived from digital R'dG'dB'd
 * (8 bits per sample, each using the full range with
 * zero representing black and 255 representing white)
 * according to the following equations:
 */


#if 0
static double rgb2y_ref(int r, int g, int b)
{
	return 16.0 + (65.738*r)/256 + (129.057*g)/256 + (25.064*b)/256;
}

static double rgb2u_ref(int r, int g, int b)
{
	return 128 - 37.945*r/256 - 74.494*g/256 + 112.439*b/256;
}

static double rgb2v_ref(int r, int g, int b)
{
	return 128 + 112.439*r/256 - 94.154*g/256 - 18.285*b/256;
}
#endif


#define CLIP(X) ( (X) > 255 ? 255 : (X) < 0 ? 0 : X)


/* RGB -> YUV */
#define RGB2Y(R, G, B) \
	CLIP(( (  66 * (R) + 129 * (G) +  25 * (B) + 128) >> 8) +  16)
#define RGB2U(R, G, B) \
	CLIP(( ( -38 * (R) -  74 * (G) + 112 * (B) + 128) >> 8) + 128)
#define RGB2V(R, G, B) \
	CLIP(( ( 112 * (R) -  94 * (G) -  18 * (B) + 128) >> 8) + 128)


#define test_vid_rgb2yuv_color(r, g, b)			\
							\
	TEST_EQUALS(RGB2Y(r, g, b), rgb2y(r, g, b));	\
	TEST_EQUALS(RGB2U(r, g, b), rgb2u(r, g, b));	\
	TEST_EQUALS(RGB2V(r, g, b), rgb2v(r, g, b));


static int test_vid_rgb2yuv(void)
{
	int r, g, b;
	int err = 0;

	/* combine 2 color components */
	for (r=0; r<256; r++) {
		for (g=0; g<256; g++) {
			test_vid_rgb2yuv_color(r, g, 0);
		}
	}

	for (r=0; r<256; r++) {
		for (b=0; b<256; b++) {
			test_vid_rgb2yuv_color(r, 0, b);
		}
	}

	for (g=0; g<256; g++) {
		for (b=0; b<256; b++) {
			test_vid_rgb2yuv_color(0, g, b);
		}
	}

 out:
	return err;
}


static bool vidframe_cmp(const struct vidframe *a, const struct vidframe *b)
{
	int i;

	if (!a || !b)
		return false;

	if (a->fmt != b->fmt)
		return false;

	for (i=0; i<4; i++) {

		if (a->linesize[i] != b->linesize[i])
			return false;

		if (!a->data[i] != !b->data[i])
			return false;

		if (a->data[i] && b->data[i]) {

			if (memcmp(a->data[i], b->data[i], a->linesize[i]))
				return false;
		}
	}

	return vidsz_cmp(&a->size, &b->size);
}


static void vidframe_dump(const struct vidframe *f)
{
	int i;

	if (!f)
		return;

	(void)re_printf("vidframe %u x %u:\n", f->size.w, f->size.h);

	for (i=0; i<4; i++) {

		if (f->linesize[i] && f->data[i]) {

			(void)re_printf("%d: %u bytes [%w]\n",
					i, f->linesize[i], f->data[i],
					(size_t)min(f->linesize[i], 16));
		}
	}
}


static void write_pattern(uint8_t *buf, size_t len)
{
	size_t i;

	for (i=0; i<len; i++)
		buf[i] = (uint8_t)i;
}


/**
 * Test vidconv module by scaling a random image up and then down.
 * The two images should then be pixel accurate.
 */
static int test_vidconv_scaling_base(enum vidfmt via_fmt)
{
	enum { WIDTH = 40, HEIGHT = 30, SCALE = 2 };
	struct vidframe *f0 = NULL, *f1 = NULL, *f2 = NULL;
	const struct vidsz size0 = {WIDTH, HEIGHT};
	const struct vidsz size1 = {WIDTH*SCALE, HEIGHT*SCALE};
	struct vidrect rect1 = {0, 0, WIDTH*SCALE, HEIGHT*SCALE};
	struct vidrect rect2 = {0, 0, WIDTH, HEIGHT};
	int i, err = 0;

	err |= vidframe_alloc(&f0, VID_FMT_YUV420P, &size0);
	err |= vidframe_alloc(&f1, via_fmt, &size1);
	err |= vidframe_alloc(&f2, VID_FMT_YUV420P, &size0);
	if (err)
		goto out;

	/* generate a random image */
	for (i=0; i<4; i++) {

		if (f0->data[i])
			write_pattern(f0->data[i], f0->linesize[i]);
	}

	vidconv(f1, f0, &rect1);
	vidconv(f2, f1, &rect2);

	if (!vidframe_cmp(f2, f0)) {

		vidframe_dump(f0);
		vidframe_dump(f2);

		err = EBADMSG;
		goto out;
	}

 out:
	mem_deref(f2);
	mem_deref(f1);
	mem_deref(f0);

	return err;
}


/*
 * verify that pixel conversion between different planar and packed
 * pixel formats is working
 */
int test_vidconv_pixel_formats(void)
{
	struct plane {
		size_t sz;
		const char *data;
	};
	static const struct test {
		enum vidfmt src_fmt;
		struct plane src_planev[3];
		enum vidfmt dst_fmt;
		struct plane dst_planev[3];
	} testv [] = {

		/* UYVY422 to YUV420P */
		{
			VID_FMT_UYVY422,
			{ {32,
			   "\x20\x00\x30\x01"
			   "\x21\x02\x31\x03"
			   "\x20\x04\x30\x05"
			   "\x21\x06\x31\x07"
			   "\x22\x08\x32\x09"
			   "\x23\x0a\x33\x0b"
			   "\x22\x0c\x32\x0d"
			   "\x23\x0e\x33\x0f"},
			  {0,0},
			  {0,0}
			},

			VID_FMT_YUV420P,
			{ {16,
			   "\x00\x01\x02\x03\x04\x05\x06\x07"
			   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"},
			  {4, "\x20\x21\x22\x23"},
			  {4, "\x30\x31\x32\x33"}
			},
		},

		/* NV12 to YUV420P */
		{
			VID_FMT_NV12,
			{ {16,
			   "\x00\x01\x02\x03\x04\x05\x06\x07"
			   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"},
			  {8, "\x20\x30\x21\x31\x22\x32\x23\x33"},
			  {0,0}
			},

			VID_FMT_YUV420P,
			{ {16,
			   "\x00\x01\x02\x03\x04\x05\x06\x07"
			   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"},
			  {4, "\x20\x21\x22\x23"},
			  {4, "\x30\x31\x32\x33"}
			},
		},

		/* YUV420P to NV12 */
		{
			VID_FMT_YUV420P,
			{ {16,
			   "\x00\x01\x02\x03\x04\x05\x06\x07"
			   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"},
			  {4, "\x20\x21\x22\x23"},
			  {4, "\x30\x31\x32\x33"}
			},

			VID_FMT_NV12,
			{ {16,
			   "\x00\x01\x02\x03\x04\x05\x06\x07"
			   "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"},
			  {8, "\x20\x30\x21\x31\x22\x32\x23\x33"},
			  {0,0}
			},
		},

#if 0
		/* RGB32 to YUV444P */
		{
			VID_FMT_RGB32,
			{ { (16*4),
			    "\x00\x00\x00\x00" "\x00\x00\x00\x00" /* black */
			    "\xff\x00\x00\x00" "\xff\x00\x00\x00" /* red */
			    "\x00\xff\x00\x00" "\x00\xff\x00\x00" /* green */
			    "\x00\x00\xff\x00" "\x00\x00\xff\x00" /* blue */
			    "\xff\x00\xff\x00" "\xff\x00\xff\x00"
			    "\x00\xff\xff\x00" "\x00\xff\xff\x00"
			    "\xff\xff\x00\x00" "\xff\xff\x00\x00"
			    "\xff\xff\xff\xff" "\xff\xff\xff\xff"},/* white */

			  {0, ""},
			  {0, ""}
			},

			VID_FMT_YUV444P,
			{ {16,
			   "\x10\x10\x29\x29" "\x90\x90\x52\x52"
			   "\x6b\x6b\xd2\xd2" "\xa9\xa9\xeb\xeb"},
			  {16,
			   "\x80\x80\xf0\xf0" "\x36\x36\x5a\x5a"
			   "\xca\xca\x10\x10" "\xa6\xa6\x80\x80"},
			  {16,
			   "\x80\x80\x6e\x6e" "\x22\x22\xf0\xf0"
			   "\xde\xde\x92\x92" "\x10\x10\x80\x80"},
			},
		},
#endif

	};
	struct vidframe *fsrc = NULL, *fdst = NULL;
	const struct vidsz sz = {4, 4};
	unsigned i, p;
	int err = 0;

	for (i=0; i<RE_ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];

#if 0
		re_printf("test[%u] %s to %s\n", i,
			  vidfmt_name(test->src_fmt),
			  vidfmt_name(test->dst_fmt));
#endif

		err |= vidframe_alloc(&fsrc, test->src_fmt, &sz);
		err |= vidframe_alloc(&fdst, test->dst_fmt, &sz);
		if (err)
			goto out;

		for (p=0; p<3; p++) {
			if (test->src_planev[p].sz) {
				memcpy(fsrc->data[p],
				       test->src_planev[p].data,
				       test->src_planev[p].sz);
			}
		}

		vidconv(fdst, fsrc, 0);

		for (p=0; p<3; p++) {

			size_t size = test->dst_planev[p].sz;

			if (!test->dst_planev[p].data)
				continue;

			TEST_MEMCMP(test->dst_planev[p].data,
				    test->dst_planev[p].sz,
				    fdst->data[p],
				    size);
		}

		fdst = mem_deref(fdst);
		fsrc = mem_deref(fsrc);
	}

 out:
	mem_deref(fsrc);
	mem_deref(fdst);

	return err;
}


static int test_vidconv_center(void)
{
	int err = 0;
	struct vidframe *dst = NULL;
	struct vidframe *src = NULL;

	struct test {
		struct vidrect r;
		struct vidsz src_sz;
		struct vidsz dst_sz;
	} testv[] = {
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 320, .h = 180},
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 180, .h = 320},
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 1920, .h = 1080},
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 1080, .h = 1920},
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 640, .h = 720},
		 .src_sz = {.w = 1920, .h = 1080},
		 .dst_sz = {.w = 1280, .h = 720}},
		{.r	 = {.x = 960, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 1024, .h = 768}, /* 4:3 */
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 320, .h = 320}, /* square */
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 1080},
		 .src_sz = {.w = 1078, .h = 1080}, /* yoffs underflow */
		 .dst_sz = {.w = 1920, .h = 1080}},
		{.r	 = {.x = 0, .y = 0, .w = 960, .h = 900},
		 .src_sz = {.w = 1080, .h = 1080}, /* xoffs underflow */
		 .dst_sz = {.w = 1920, .h = 1296}},
	};

	for (size_t i = 0; i < RE_ARRAY_SIZE(testv); i++) {
		struct test *test    = &testv[i];

		err = vidframe_alloc(&src, VID_FMT_YUV420P, &test->src_sz);
		err |= vidframe_alloc(&dst, VID_FMT_YUV420P, &test->dst_sz);
		TEST_ERR(err);

		vidconv_center(dst, src, &test->r);

		src = mem_deref(src);
		dst = mem_deref(dst);
	}

out:
	src = mem_deref(src);
	dst = mem_deref(dst);

	return err;
}


int test_vidconv(void)
{
	int err;

	err = test_vid_rgb2yuv();
	TEST_ERR(err);

	err = test_vidconv_center();
	TEST_ERR(err);

out:
	return err;
}


int test_vidconv_scaling(void)
{
	int err;

	err = test_vidconv_scaling_base(VID_FMT_YUV420P);
	TEST_ERR(err);

	err = test_vidconv_scaling_base(VID_FMT_NV12);
	TEST_ERR(err);

out:
	return err;
}
