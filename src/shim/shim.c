/**
 * @file re_shim.h  Interface to SHIM layer
 *
 * Copyright (C) 2015 - 2022 Alfred E. Heggestad
 */

#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_tcp.h>
#include <re_net.h>
#include <re_shim.h>
#include <re_convert.h>


#define DEBUG_MODULE "shim"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


struct shim {
	struct tcp_conn *tc;
	struct tcp_helper *th;
	struct mbuf *mb;
	shim_frame_h *frameh;
	void *arg;

	uint64_t n_tx;
	uint64_t n_rx;
};


/* responsible for adding the SHIM header
   - assumes that the sent MBUF contains a complete packet
 */
static bool shim_send_handler(int *err, struct mbuf *mb, void *arg)
{
	struct shim *shim = arg;
	int err_len;
	uint16_t len;
	(void)shim;

	if (mb->pos < SHIM_HDR_SIZE) {
		DEBUG_WARNING("send: not enough space for SHIM header\n");
		*err = ENOMEM;
		return true;
	}

	err_len = try_into_u16_from_size(&len, mbuf_get_left(mb));
	if (err_len) {
		DEBUG_WARNING("send: mbuf to big\n");
		*err = err_len;
		return true;
	}

	mb->pos -= SHIM_HDR_SIZE;
	*err = mbuf_write_u16(mb, htons(len));
	mb->pos -= SHIM_HDR_SIZE;

	++shim->n_tx;

	return false;
}


static bool shim_recv_handler(int *errp, struct mbuf *mbx, bool *estab,
			      void *arg)
{
	struct shim *shim = arg;
	int err = 0;
	(void)estab;

	/* handle re-assembly */
	if (!shim->mb) {
		shim->mb = mbuf_alloc(1024);
		if (!shim->mb) {
			*errp = ENOMEM;
			return true;
		}
	}

	if (shim->mb) {
		size_t pos;

		pos = shim->mb->pos;

		shim->mb->pos = shim->mb->end;

		err = mbuf_write_mem(shim->mb, mbuf_buf(mbx),
				     mbuf_get_left(mbx));
		if (err)
			goto out;

		shim->mb->pos = pos;
	}

	/* extract all SHIM-frames in the TCP-stream */
	for (;;) {

		size_t start, len, pos, end;
		bool hdld;

		start = shim->mb->pos;

		if (mbuf_get_left(shim->mb) < (SHIM_HDR_SIZE))
			break;

		len = ntohs(mbuf_read_u16(shim->mb));

		if (mbuf_get_left(shim->mb) < len)
			goto rewind;

		pos = shim->mb->pos;
		end = shim->mb->end;

		shim->mb->end = pos + len;

		++shim->n_rx;

		hdld = shim->frameh(shim->mb, shim->arg);
		if (!hdld) {
			/* XXX: handle multiple frames per segment */

			shim->mb->pos = pos;
			shim->mb->end = pos + len;

			mbx->pos = mbx->end = 2;
			err = mbuf_write_mem(mbx, mbuf_buf(shim->mb), len);
			if (err)
				goto out;
			mbx->pos = 2;

			shim->mb->pos = pos + len;
			shim->mb->end = end;

			return false;  /* continue recv-handlers */
		}

		shim->mb->pos = pos + len;
		shim->mb->end = end;

		if (shim->mb->pos >= shim->mb->end) {
			shim->mb = mem_deref(shim->mb);
			break;
		}

		continue;

	rewind:
		shim->mb->pos = start;
		break;
	}

 out:
	if (err)
		*errp = err;

	return true;  /* always handled */
}


static void destructor(void *arg)
{
	struct shim *shim = arg;

	mem_deref(shim->th);
	mem_deref(shim->tc);
	mem_deref(shim->mb);
}


int shim_insert(struct shim **shimp, struct tcp_conn *tc, int layer,
		shim_frame_h *frameh, void *arg)
{
	struct shim *shim;
	int err;

	if (!shimp || !tc || !frameh)
		return EINVAL;

	shim = mem_zalloc(sizeof(*shim), destructor);
	if (!shim)
		return ENOMEM;

	shim->tc = mem_ref(tc);
	err = tcp_register_helper(&shim->th, tc, layer, NULL,
				  shim_send_handler,
				  shim_recv_handler, shim);
	if (err)
		goto out;

	shim->frameh = frameh;
	shim->arg = arg;

 out:
	if (err)
		mem_deref(shim);
	else
		*shimp = shim;

	return err;
}


int shim_debug(struct re_printf *pf, const struct shim *shim)
{
	if (!shim)
		return 0;

	return re_hprintf(pf, "tx=%llu, rx=%llu", shim->n_tx, shim->n_rx);
}
