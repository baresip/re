#!/usr/bin/python
#
# Copyright (C) 2025 Alfred E. Heggestad
#

import scipy.signal

TAPS = 31
CUTOFF = 8000.0   # Hz
SRATE = 16000.0   # Hz

cutoff = CUTOFF / SRATE


coeffs = scipy.signal.firwin(TAPS, cutoff)


print "/*"
print " * FIR filter with cutoff %dHz, samplerate %dHz" % (CUTOFF, SRATE)
print " */"
print "static const int16_t fir_lowpass[%d] = {" % (TAPS)

i = 0

for c in coeffs:
    v = int(c * 32768.0)

    print " %5d," % (v),

    i += 1
    if not (i % 8):
        print "\n" ,

print ""
print "};"
