This adaptive audio buffer implementation increases the number of packets in
the buffer during periods of high network jitter. It reduces the number of
packets if the network condition improves.


## Computing the jitter

The network jitter is computed similar to the proposition in RFC-3550 RTP
section A.8 and similar how wireshark does it. The jitter is an exponential
moving average (EMA) of the difference *d* between the real time and the RTP
timestamps. Or more concretely we compute at each `ajb_calc()` the difference

*d = Dt<sub>r</sub> -  Dt<sub>s</sub>*,

where *Dt<sub>r</sub>* is the real time elapsed from last call to
`ajb_calc()` and  *Dt<sub>s</sub>* is the difference of the timestamps. Then
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

When a Low situation is detected we increase the number of packets in `aubuf`
by holding back a packet during one call to function `aubuf_read_auframe()`.
While when a High situation is detected we reduce the number of packets by
reading another audio frame. This overwrites one frame. By means of a silence
detection `aubuf` is able to drop frames that are not important for the speech
quality. This reduces the audio latency down to the value before the High
situation.


## Computing a smooth latency

The audio frames that are buffered at a concrete point in time in `aubuf` lead
to a temporary latency value l<sub>c</sub>. Let *f<sub>0</sub>, ...,
f<sub>m</sub>* be the audio frames currently stored in `aubuf`. Then

*l<sub>c</sub> = t<sub>m</sub> - t<sub>0</sub> + t<sub>p</sub>*,

where *t<sub>i</sub>* is the timestamp of frame *f<sub>i</sub>* and
*t<sub>p</sub>* is the packet time `ptime`. The packet time is a
constant that is specified at the beginning of a SIP call. In baresip it is
specified in the account file.

The temporary latency *l<sub>c</sub>* is discontinuous over time and not
adequate for deciding or detecting Low or High situations. Therefore we again
use a exponential moving average (EMA) to smooth *l<sub>c</sub>*. Let *s* be an
adequate moving average speed, then the smoothed latency

*l = l + s (l<sub>c</sub> - l)*.

Low/High situations are decided when the smoothed latency *l* runs out of some
boundaries that are computed from the jitter.

## Deciding Low/High situations

During each iteration (each `aubuf_write_frame()`) the jitter and the latency
are computed. Additionally we compute the bottom boundary *l<sub>b</sub>* and
the top boundary *l<sub>t</sub>* with

*l<sub>b</sub> = 1.25 j* and

*l<sub>t</sub> = 2.2 j*.

Since we want to respect also the parameter `min` of function `aubuf_alloc()`
we extend these formulas. Let *m<sub>m</sub>* be the parameter `min`. Then

*l<sub>b</sub> = max(m<sub>m</sub> 2 t<sub>p</sub> / 3, 1.25 j)* and

*l<sub>t</sub> = max(l<sub>b</sub> + 4 t<sub>p</sub> / 3, 2.2 j)*,

where *t<sub>p</sub>* is the `ptime` as defined already. Finally we have
everything for deciding Low and High situations. That is if *l* moves out of
the boundaries

*l<sub>b</sub> < l < l<sub>t</sub>*

then we fire a Low/High.

## Early adjustment of the latency

Finally, if we detect a Low/High situation we increase/reduce the number of
packets. Now we immediately increment/decrement the smoothed latency *l* by
one packet time. Thus early adjustment for a Low situation is

*l = l + l<sub>p</sub>* and for a High situation
*l = l - l<sub>p</sub>*.

This avoids multiple Low/High detections in a row.

## Silence detection

It is preferable to drop an audio frame only if it contains nearly silence.

## Math symbols vs. C-variables

In order to avoid float computation we use micro seconds to measure the time
differences, the jitter and buffer time. Symbols used in this document are
mapped to the C-variables in `src/aubuf/ajb.c` like this table shows:


Symbol|Variable
------|--------
*d*   | `d`
*j*   | `jitter`
*l*   | `avbuftime`
*l<sub>c</sub>*   | `buftime`
*l<sub>b</sub>*   | `bufmin`
*l<sub>t</sub>*   | `bufmax`
*t<sub>p</sub>*   | `ptime`


## How to test adaptive aubuf

- In aubuf.c set DEBUG\_LEVEL to 6, build and install libre again!

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

- See/Use ajb.plot to generate a plot!

Note:
- Activate and deactivate the network jitter during a call to see how the
adaptive audio buffer algorithm works!
- You need a very new kernel or at least some patches for the `sch_netem`
kernel module. There was a problem which lead to many reordered and very late
RTP packets. Be sure that you have this commit in the kernel:
```
commit eadd1befdd778a1eca57fad058782bd22b4db804
Author: Aleksandr Nogikh <nogikh@google.com>
Date:   Wed Oct 28 17:07:31 2020 +0000

    netem: fix zero division in tabledist
```
