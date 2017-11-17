#!/usr/bin/env python

import os
import glob
import sys
import signal
import subprocess

# path = '/home/gnomex/HomeWorkMalwareAnalysis/Pcaps'
path = '/media/gnomex/zebras/kenner-pcaps'
src_path = '/home/gnomex/HomeWorkMalwareAnalysis/analysis/bad_pcaps'
new_path = '/home/gnomex/HomeWorkMalwareAnalysis/analysis/rlly_bad_pcaps'

PID = None

try:
    for filename in glob.glob(os.path.join(path, '*.pcap')):
        print("Reading {}".format(filename))

        try:
            # append _entropy_hcurve.jpg
            proc = subprocess.Popen(["mv {}/{}_entropy_hcurve.jpg {}".format(src_path, os.path.basename(filename), new_path)], shell=True)
            PID = proc.pid
            proc.wait()
        except Exception as e:
            print("Something wrong here, file {}, exc {}".format(filename, e))
            if PID:
                proc.terminate()
            raise

except (KeyboardInterrupt, SystemExit):
    print("From lol: interrupt received, stopping...")
    sys.exit(-1)
