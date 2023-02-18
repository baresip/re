/**
 * @file sipevent.c SIP Event regression testcode
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "test_sipevent"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * A is the subscriber to event changes from B
 *
 *   .-----.               .-----.
 *   |  A  |               |  B  |
 *   '-----'               '-----'
 * (Subscriber)           (Notifier)
 *
 *       ----- SUBSCRIBE ----->
 *
 *       <----- 200 OK --------
 *
 *
 *
 *
 *                             <------- X somekind of event happened
 *       <----- NOTIFY --------
 *  X <--
 *       ------- 200 OK ------>
 *
 */


struct agent {
	struct agent *peer;
	struct sip *sip;
	struct sipevent_sock *sock;
	struct sipsub *sub;
	struct sipnot *not;
	char name[32];
	bool exited;
	char uri[256];
	unsigned subc;
	unsigned notc;
	unsigned closec;
	int err;
};


static const char *test_event = "my-event";


static void complete(struct agent *ag, int err)
{
	ag->err = err;
	re_cancel();
}


static int send_notify(struct agent *ag)
{
	const char *aor = "tull";
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err = mbuf_printf(mb,
	"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\r\n"
	"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"\r\n"
	"    xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\"\r\n"
	"    xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\"\r\n"
	"    entity=\"%s\">\r\n"
	"  <dm:person id=\"p4159\"><rpid:activities/></dm:person>\r\n"
	"  <tuple id=\"t4109\">\r\n"
	"    <status>\r\n"
	"      <basic>%s</basic>\r\n"
	"    </status>\r\n"
	"    <contact>%s</contact>\r\n"
	"  </tuple>\r\n"
	"</presence>\r\n"
		    ,aor, "open", aor);
	if (err)
		goto out;

	mb->pos = 0;

	err = sipevent_notify(ag->not, mb, SIPEVENT_ACTIVE, 0, 0);
	if (err) {
		DEBUG_WARNING("presence: notify to %s failed (%m)\n",
			      aor, err);
	}

 out:
	mem_deref(mb);
	return err;
}


static void sipnot_close_handler(int err, const struct sip_msg *msg,
				 void *arg)
{
	struct agent *ag = arg;
	(void)msg;

	DEBUG_WARNING("[ %s ] sip notification closed (%m)\n",
		      ag->name, err);

	++ag->closec;

	complete(ag, err);
}


/*
 * Agent `B' -- the Notifier
 *
 * Handle incoming SUBSCRIBE message from A

SUBSCRIBE sip:b@127.0.0.1:20000 SIP/2.0.
Via: SIP/2.0/UDP 127.0.0.1:10000;branch=z9hG4bKf7f2e9e48bbaea6b;rport.
Contact: <sip:a@127.0.0.1:10000>.
Max-Forwards: 70.
To: <sip:b@127.0.0.1:20000>.
From: "a" <sip:a@127.0.0.1:10000>;tag=d3d00d9fb5ee45d5.
Call-ID: 26ac32ea11a58011.
CSeq: 37745 SUBSCRIBE.
User-Agent: a.
Event: my-event.
Expires: 600.
Content-Length: 0.


 */
static bool subscribe_handler(const struct sip_msg *msg, void *arg)
{
	struct agent *ag = arg;
	struct agent *peer = ag->peer;
	const struct sip_hdr *hdr;
	struct sipevent_event se;
	int err = 0;

	DEBUG_INFO("[ %s ] recv SIP msg (%r)\n", ag->name, &msg->met);

	++ag->subc;

	TEST_ASSERT(msg != NULL);
	TEST_STRCMP("SUBSCRIBE", 9U, msg->met.p, msg->met.l);
	hdr = sip_msg_hdr(msg, SIP_HDR_CONTACT);
	TEST_ASSERT(hdr != NULL);
	TEST_STRCMP(ag->uri, strlen(ag->uri), msg->to.auri.p, msg->to.auri.l);
	TEST_STRCMP(peer->uri, strlen(peer->uri),
		    msg->from.auri.p, msg->from.auri.l);
	TEST_STRCMP("SUBSCRIBE", 9U, msg->cseq.met.p, msg->cseq.met.l);
	TEST_ASSERT(pl_u32(&msg->expires) > 0);

	hdr = sip_msg_hdr(msg, SIP_HDR_EVENT);
	if (!hdr) {
		err = EPROTO;
		goto out;
	}

	err = sipevent_event_decode(&se, &hdr->val);
	if (err)
		goto out;

	if (pl_strcasecmp(&se.event, test_event)) {
		DEBUG_WARNING("presence: unexpected event '%r'\n", &se.event);
		err = EPROTO;
		goto out;
	}

	err = sipevent_accept(&ag->not, ag->sock, msg, NULL, &se, 200, "OK",
			      600, 600, 600, ag->name, "application/pidf",
			      NULL, NULL, false,
			      sipnot_close_handler, ag, NULL);
	if (err)
		goto out;

	err = send_notify(ag);
	if (err)
		goto out;

 out:
	if (err) {
		complete(ag, err);
	}

	return true;
}


/*
 * Agent `A' -- the Subscriber
 *
 * handle incoming NOTIFY messages from B
 *

NOTIFY sip:a@127.0.0.1:10000 SIP/2.0.
Via: SIP/2.0/UDP 127.0.0.1:20000;branch=z9hG4bK056ce9e0dabdea16;rport.
Contact: <sip:b@127.0.0.1:20000>.
Max-Forwards: 70.
To: "a" <sip:a@127.0.0.1:10000>;tag=b8c2a38adecb1bea.
From: <sip:b@127.0.0.1:20000>;tag=426f09aed9f32053.
Call-ID: f3b22da3f4223935.
CSeq: 7364 NOTIFY.
User-Agent: b.
Event: my-event.
Subscription-State: active;expires=600.
Content-Type: application/pidf.
Content-Length: 417.

 */
static void sipsub_notify_handler(struct sip *sip, const struct sip_msg *msg,
				  void *arg)
{
	struct agent *ag = arg;
	struct agent *peer = ag->peer;
	const struct sip_hdr *hdr;
	struct sipevent_substate substate;
	int err = 0;
	(void)sip;

	DEBUG_INFO("[ %s ] subscriber -- incoming notify\n", ag->name);

	TEST_ASSERT(NULL != ag->sub);

	++ag->notc;

	/* verify the SIP message */
	TEST_ASSERT(msg != NULL);
	TEST_STRCMP("NOTIFY", 6U, msg->met.p, msg->met.l);
	hdr = sip_msg_hdr(msg, SIP_HDR_CONTACT);
	TEST_ASSERT(hdr != NULL);
	TEST_STRCMP(ag->uri, strlen(ag->uri), msg->to.auri.p, msg->to.auri.l);
	TEST_STRCMP(peer->uri, strlen(peer->uri),
		    msg->from.auri.p, msg->from.auri.l);
	TEST_STRCMP("NOTIFY", 6U, msg->cseq.met.p, msg->cseq.met.l);
	hdr = sip_msg_hdr(msg, SIP_HDR_EVENT);
	TEST_ASSERT(hdr != NULL);
	TEST_STRCMP(test_event, str_len(test_event), hdr->val.p, hdr->val.l);

	hdr = sip_msg_hdr(msg, SIP_HDR_SUBSCRIPTION_STATE);
	TEST_ASSERT(hdr != NULL);
	err = sipevent_substate_decode(&substate, &hdr->val);
	TEST_ERR(err);

	/* verify that state is active */
	TEST_EQUALS(SIPEVENT_ACTIVE, substate.state);
	TEST_ASSERT(pl_u32(&substate.expires) > 0);

	sip_treply(NULL, sip, msg, 200, "OK");

	complete(ag, 0);
	return;

 out:
	if (err)
		complete(ag, err);
}


static void sipsub_close_handler(int err, const struct sip_msg *msg,
				 const struct sipevent_substate *substate,
				 void *arg)
{
	struct agent *ag = arg;
	(void)msg;
	(void)substate;

	DEBUG_WARNING("[ %s ] subscriber -- closed (%m)\n", ag->name, err);

	++ag->closec;

	complete(ag, err);
}


static void exit_handler(void *arg)
{
	struct agent *ag = arg;

	ag->exited = true;

	if (ag->peer->exited)
		re_cancel();
}


static void destructor(void *data)
{
	struct agent *ag = data;

	mem_deref(ag->sub);
	mem_deref(ag->not);

	mem_deref(ag->sock);

	sip_close(ag->sip, true);
	mem_deref(ag->sip);
}


static int agent_alloc(struct agent **agp, const char *name,
		const struct sa *laddr)
{
	struct sa sa;
	struct agent *ag;
	int err;

	ag = mem_zalloc(sizeof(*ag), destructor);
	if (!ag)
		return ENOMEM;

	str_ncpy(ag->name, name, sizeof(ag->name));

	err = sip_alloc(&ag->sip, NULL, 32, 32, 32,
			name, exit_handler, ag);
	if (err)
		goto out;

	err = sip_transp_add(ag->sip, SIP_TRANSP_UDP, laddr);
	if (err)
		goto out;

	err = sip_transp_laddr(ag->sip, &sa, SIP_TRANSP_UDP, NULL);
	if (err)
		goto out;

	err = sipevent_listen(&ag->sock, ag->sip, 32, 32,
			      subscribe_handler, ag);
	if (err)
		goto out;

	re_snprintf(ag->uri, sizeof(ag->uri), "sip:%s@%J", name, &sa);

#if 0
	re_printf("agent %s (%s)\n", name, ag->uri);
#endif

 out:
	if (err)
		mem_deref(ag);
	else
		*agp = ag;

	return err;
}


static int agent_subscribe(struct agent *ag, struct agent *peer)
{
	if (!ag || !peer)
		return EINVAL;

	return sipevent_subscribe(&ag->sub, ag->sock, peer->uri, ag->name,
				  ag->uri, test_event, NULL, 600, ag->name,
				  NULL, 0, NULL, NULL, false,
				  NULL, sipsub_notify_handler,
				  sipsub_close_handler, ag, NULL);
}


static int do_sipevent(struct sa *laddr)
{
	struct agent *a = NULL, *b = NULL;
	int err = 0;

	err = agent_alloc(&a, "a", laddr);
	if (err)
		goto out;
	err = agent_alloc(&b, "b", laddr);
	if (err)
		goto out;

	a->peer = b;
	b->peer = a;

	err = agent_subscribe(a, b);
	if (err)
		goto out;

	err = re_main_timeout(500);
	if (err)
		goto out;

	TEST_ERR(a->err);
	TEST_ERR(b->err);

	TEST_EQUALS(0, a->subc);
	TEST_EQUALS(1, a->notc);
	TEST_EQUALS(0, a->closec);

	TEST_EQUALS(1, b->subc);
	TEST_EQUALS(0, b->notc);
	TEST_EQUALS(0, b->closec);

 out:
	mem_deref(b);
	mem_deref(a);

	return err;
}


int test_sipevent(void)
{
	int err;
	struct sa laddr;

	err = sa_set_str(&laddr, "127.0.0.1", 0);
	TEST_ERR(err);

	err = do_sipevent(&laddr);

out:
	return err;
}


int test_sipevent_network(void)
{
	struct sa laddr;
	int err = 0;

	sa_init(&laddr, AF_INET6);

	if (0 == net_if_getlinklocal(NULL, AF_INET6, &laddr)) {

		err = do_sipevent(&laddr);
	}

	return err;
}
