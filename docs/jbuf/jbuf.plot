#!/usr/bin/gnuplot
#
# How to generate a plot
# ======================
# This gnuplot script plots DEBUG_LEVEL 6 output of jbuf.c. You have to
# increment the DEBUG_LEVEL in jbuf.c if you want to get the table for
# jbuf.dat. Then call baresip like this:
#
# ./baresip 2>&1 | grep -Eo "plot_stat.*" jbuf.log > jbuf.dat
#
# Call this script. Then compare the plot legend with the variables in jbuf.c!
#
#
# Description of the plot
# =======================
# The plot is a time based diagram. The values avbuftime should lie between
# bufmin and bufmax. If it runs somewhere out of these boundaries (and stays
# outside for a while) a "Low" / "High" situation is detected.
#
# "Good" means: The number of packets in the jitter buffer is ok.
#
# "Low" means:  The number is too low. Then the packets are incremented by
#               holding one packet back in jbuf_get().
#
# "High" means: The number is to high. Then packets are decremented by dropping
#               one packet in jbuf_put(). This reduces the audio delay.
#
# The number of "Low"/"High" situations should be low while buffer under-runs
# should be avoided completely.

# On the x-axes of the plot there is the time in milliseconds. See function
# jbuf_jitter_calc()! We note the variables in jbuf.c here in parentheses.
#  E.g. (var jitter).
#
# - The orange line is the computed network jitter (var jitter). This is a
#   moving average of the difference (var d) between the real time diff
#   (var tr - var tr0) and the RTP timestamps diff (var ts - var ts0).
#   See RFC-3550 RTP - A.8!
#   We suggest a fast rise of the moving average and a slow shrink. Thus
#   avoiding buffer under-runs have a higher priority than reducing the audio
#   delay.
#
# - The buftime (var buftime) is the difference of the timestamps between the
#   last RTP packet and the first RTP packet stored in the jbuf plus one packet
#   time (var ptime) for the last packet.
#   The buftime (light-grey) changes very fast during periods of jitter. To be
#   applicable for detecting "Low" or "High" situations it has to be smoothed.
#   The blue line avbuftime (var avbuftime) is a moving average of the buftime
#   and is used to detect "Low"/"High". Thus the jbuf algorithm tries to keep
#   the avbuftime between the following boundaries.
#
# - The green lines bufmin and bufmax (var bufmin, bufmax) are boundaries for
#   avbuftime.They are computed by constant factors (> 1.) from the jitter.
#
#
# Copyright (C) 2020 commend.com - Christian Spielberger, Michael Peitler


# Choose your preferred gnuplot terminal or use e.g. evince to view the
# jbuf.eps!

#set terminal x11
set terminal postscript eps size 15,10 enhanced color
set output 'jbuf.eps'
#set terminal png size 1280,480
#set output 'jbuf.png'
set datafile separator ","
set key outside
plot \
'jbuf.dat' using 2:4 title 'jitter' with linespoints linecolor "orange", \
'jbuf.dat' using 2:6 title 'avbuftime' with linespoints linecolor "skyblue", \
'jbuf.dat' using 2:7 title 'bufmin' with linespoints linecolor "sea-green", \
'jbuf.dat' using 2:8 title 'bufmax' with linespoints linecolor "sea-green", \
'jbuf.dat' using 2:($9*10) title 'Good/Empty/Low/High' linecolor "red", \
'jbuf.dat' using 2:5 title 'buftime' linecolor "light-grey", \
10 title "Empty=10" linecolor "red", \
20 title "Low=20" linecolor "red", \
30 title "High=30" linecolor "red"

