#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>


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
