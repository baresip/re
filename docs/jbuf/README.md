This adaptive jitter buffer implementation increases the number of packets in
the buffer during periods of high network jitter. It reduces the number of
packets if the network condition improves.


## Computing the jitter

The network jitter is computed similar to the proposition in RFC-3550 RTP
section A.8 and similar how wireshark does it. The jitter is a moving average
of the difference *d* between the real time and the RTP timestamps. Or more
concretely we compute at each `jbuf_put()` the difference

*d = Dt<sub>r</sub> -  Dt<sub>s</sub>*,

where *Dt<sub>r</sub>* is the real time elapsed from last call to
`jbuf_put` and  *Dt<sub>s</sub>* is the difference of the timestamps. Then
with a predefined speed *s* we compute the jitter *j* as moving average

*j = j + s (|d| - j)*.

We choose a higher value for speed *s* if *|d| > j*. Thus the jitter rises fast
if e.g. suddenly a network jitter appears. In contrast when the network
condition improves the jitter value slowly shrinks. The reason for different
rising and falling speed is that we have to react fast to avoid buffer
under-runs, whereas reducing of the latency may be done a while after the
network condition improved.

In the following sections we will describe how the computed jitter is used to
detect situations where the buffered packets should be increased due to a high
jitter. We call this situations **Low** situations. When the jitter shrinks
below some specific value it is a good idea to reduce the buffer to reduce the
audio latency. We call this situations **High** situations. Surely, the
Low/High situations have to be decided somehow.

## Reduce/Increase buffered packets

When a Low situation is detected we increase the number of packets in jbuf by
holding back a packet during one call to function `jbuf_get()`. While when
a High situation is detected we reduce the number of packets by telling baresip
to immediately call `jbuf_get()` a second time. For this purpose `jbuf_get()`
returns EAGAIN. Then baresip decodes two RTP packets and thus the audio buffer
increases by one frame. By means of a silence detection baresip is able to drop
frames that are not important for the speech quality. This reduces the audio
latency down to the value before the High situation.


## Computing a smooth latency

The RTP packets that are buffered at a concrete point in time in the jbuf lead
to a temporary latency value l<sub>c</sub>. Let *p<sub>0</sub>, ...,
p<sub>m</sub>* be the RTP packets currently stored in the jbuf. Then

*l<sub>c</sub> = t<sub>m</sub> - t<sub>0</sub> + t<sub>p</sub>*,

where *t<sub>i</sub>* is the RTP timestamp of packet *p<sub>i</sub>* and
*t<sub>p</sub>* is the packet time (`ptime` in jbuf.c). The packet time is a
constant that is specified at the beginning of a call. In baresip it is
specified in the account file.

The temporary latency *l<sub>c</sub>* is discontinuous over time and not
adequate for deciding or detecting Low or High situations. Therefore we again
use a moving average to smooth *l<sub>c</sub>*. Let *s* be an adequate moving
average speed, then the smoothed latency

*l = l + s (l<sub>c</sub> - l)*.

Low/High situations are decided when the smoothed latency *l* runs out of some
boundaries that are computed from the jitter.

## Deciding Low/High situations

During each iteration (each `jbuf_put()`) the jitter and the latency are
computed. Additionally we compute the bottom boundary *l<sub>b</sub>* and the
top boundary *l<sub>t</sub>* with

*l<sub>b</sub> = 1.25 j* and

*l<sub>t</sub> = 2.2 j*.

Since we want to respect also the parameter `min` of function `jbuf_alloc()` we
extend these formulas. Let *m<sub>m</sub>* be the parameter `min`. Then

*l<sub>b</sub> = max(m<sub>m</sub> 2 t<sub>p</sub> / 3, 1.25 j)* and

*l<sub>t</sub> = max(m<sub>m</sub> 11 t<sub>p</sub> / 3, 2.2 j)*,

where *t<sub>p</sub>* is the `ptime` as defined already. Finally we have
everything for deciding Low and High situations. That is if *l* moves out of
the boundaries

*l<sub>b</sub> < l < l<sub>t</sub>*

then we fire a Low/High.

## Early adjustment of the latency

Finally, if we detect a Low/High situation we increase/reduce the number of
packets. Now we immediately increment/decrement the smoothed latency *l* by
one packet time. So early adjustment for a Low situation is

*l = l + l<sub>p</sub>* and for a High situation
*l = l - l<sub>p</sub>*.


This avoids multiple Low/High detections in a row.


## Silence detection

It is preferable to hold back an RTP packet in `jbuf_get()` only during a
period of silence. But deciding if there is currently silence in the RTP stream
can only be done by investigating the audio frames after decoding the RTP
packet. Decoding is done in baresip. Thus we add a function `jbuf_silence()`
that sets the flag `silence`. This function has to be called by baresip.


## Math symbols vs. C-variables

In order to avoid float computation we use a constant factor
```JBUF_JITTER_PERIOD``` for all time based variables in jbuf.c. Apart from
that the symbols used here are mapped to the C-variables like this table shows:


Symbol|Variable
------|--------
*d*   | `d`
*j*   | `jitter`
*l*   | `avbuftime`
*l<sub>c</sub>*   | `buftime`
*l<sub>b</sub>*   | `bufmin`
*l<sub>t</sub>*   | `bufmax`
*t<sub>p</sub>*   | `ptime`


## Wish size

We introduce also the parameter `wish` and a setter function `jbuf_set_wish()`.
The wish size is the number of packets that will be collected at the beginning
of an RTP stream before `jbuf_get()` will return the first packet. If the user
passes `wish=0` then it is set internally to `min`. If the user knows that the
network contains jitter he may set the wish size to some adequate value. This
avoids underflows at the beginning of the stream. The `min` parameter can be
left at some lower value. When the network situation improves, the buffer is
reduced down to `min`. Thus the latency is reduced to the specified minimum.


## How to test jbuf

- In jbuf.c set DEBUG\_LEVEL to 6, build and install libre again!

- Add bridge interface linked to your Ethernet/WiFi interface! Suppose baresip
is connected to the network interface *eth0*. Replace *eth0* with your physical
network interface! See the man pages of "ip" and "tc" for further details!

```
sudo ip link add ifb1 type ifb || :
sudo ip link set ifb1 up
sudo tc qdisc add dev eth0 handle ffff: ingress
sudo tc filter add dev eth0 parent ffff: u32 match u32 0 0 action mirred egress redirect dev ifb1
```

This redirects the incoming eth0 traffic to a new ifb interface.

- How to activate the jitter. Here we set the delay to 100ms ± 50ms.
```
sudo tc qdisc add dev ifb1 root netem delay 100ms 50ms
```

- How to deactivate the jitter.
```
sudo tc qdisc del dev ifb1 root
```

- See/Use jbuf.plot to generate a plot!

Note:
- Activate and deactivate the network jitter during a call to see how the
adaptive jitter buffer algorithm works!
- You need a very new kernel or at least some patches for the sch_netem kernel
module. There was a problem which lead to many reordered and very late RTP
packets. Be sure that you have this commit in the kernel:
```
commit eadd1befdd778a1eca57fad058782bd22b4db804
Author: Aleksandr Nogikh <nogikh@google.com>
Date:   Wed Oct 28 17:07:31 2020 +0000

    netem: fix zero division in tabledist
```
