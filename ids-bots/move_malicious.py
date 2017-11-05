#!/usr/bin/env python

import os
import glob
import sys
import signal
import subprocess
import mmap

path = '/home/gnomex/HomeWorkMalwareAnalysis/Pcaps'
malware_path = '/home/gnomex/HomeWorkMalwareAnalysis/kenner-pcaps'

PID = None

try:
    for filename in glob.glob(os.path.join(path, '*.pcap')):
        print("Reading {}".format(filename))

        try:
            proc = subprocess.Popen(["docker run --rm -it -v {}:/pcap rapid7/suricata -l /pcap -k none -r /pcap/{}".format(path, os.path.basename(filename))], shell=True)
            # proc = subprocess.Popen(["docker run --rm -it -v {}:/pcap rapid7/suricata -l /pcap -k all -r /pcap/{}".format(path, os.path.basename(filename))], shell=True)
            PID = proc.pid
            proc.wait()

            if os.stat("{}/fast.log".format(path)).st_size != 0:
              # move to suspect/malicious folder
              print("malicious pcap found, moving to right folder")
              proc = subprocess.Popen(["mv {} {}/{}".format(filename, malware_path, os.path.basename(filename))], shell=True)
              PID = proc.pid
              proc.wait()
            else:
              print("Nothing found... moving on")

            os.remove("{}/fast.log".format(path))

        except Exception as e:
            print("Something wrong here, file {}, exc {}".format(filename, e))
            if PID:
                proc.terminate()
            raise

except (KeyboardInterrupt, SystemExit):
    print("From lol: interrupt received, stopping...")
    sys.exit(-1)
