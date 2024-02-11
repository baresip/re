#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_trace.h>
#include <re_mem.h>


int re_text2pcap(struct re_printf *pf, struct re_text2pcap *pcap)
{
	if (!pcap)
		return EINVAL;

	uint8_t *buf = mbuf_buf(pcap->mb);
	if (!buf)
		return EINVAL;

	re_hprintf(pf, "%s %H 000000", pcap->in ? "I" : "O", fmt_timestamp_us,
		   NULL);

	size_t sz = mbuf_get_left(pcap->mb);
	for (size_t i = 0; i < sz; i++) {
		re_hprintf(pf, " %02x", buf[i]);
	}

	re_hprintf(pf, " %s", pcap->id);

	return 0;
}


void re_text2pcap_trace(const char *name, const char *id, bool in,
			const struct mbuf *mb)
{
	struct re_text2pcap pcap = {.in = in, .mb = mb, .id = id};
	size_t pcap_buf_sz = (mbuf_get_left(mb) * 3) + 64;

	char *pcap_buf = mem_alloc(pcap_buf_sz, NULL);
	if (!pcap_buf)
		return;

	(void)re_snprintf(pcap_buf, pcap_buf_sz, "%H", re_text2pcap, &pcap);

	re_trace_event("pcap", name, 'I', NULL, RE_TRACE_ARG_STRING_COPY,
		       "pcap", pcap_buf);

	mem_deref(pcap_buf);
}
