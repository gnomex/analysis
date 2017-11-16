#!/usr/bin/env python

import os
import glob
import sys
import signal
import subprocess

# path = '/home/gnomex/HomeWorkMalwareAnalysis/Pcaps'
path = '/media/gnomex/zebras/kenner-pcaps'
# malware_path = '/home/gnomex/HomeWorkMalwareAnalysis/kenner-pcaps'
malware_path = '/media/gnomex/zebras/kenner-pcaps-good'

PID = None

try:
    for filename in glob.glob(os.path.join(path, '*.pcap')):
        print("Reading {}".format(filename))

        try:
            proc = subprocess.Popen(["docker run --rm -it -v {}:/pcap rapid7/suricata -l /pcap -k none -r /pcap/{}".format(path, os.path.basename(filename))], shell=True)
            PID = proc.pid
            proc.wait()

            proc = subprocess.Popen(["docker run --rm \
              -v {}:/pcap \
              -v /home/gnomex/HomeWorkMalwareAnalysis/bro-ids/local.bro:/usr/local/share/bro/site/local.bro blacktop/bro \
              -C -r {} local".format(path, os.path.basename(filename))], shell=True)
            PID = proc.pid
            proc.wait()

            if (os.path.isfile("{}/fast.log".format(path)) and os.stat("{}/fast.log".format(path)).st_size != 0) or (os.path.isfile("{}/notice.log".format(path)) and os.stat("{}/notice.log".format(path)).st_size != 0):
              # move to suspect/malicious folder
              # print("malicious pcap found, moving to right folder")
              print("suspect pcap!")
            else:
              print("Good pcap, moving...")
              proc = subprocess.Popen(["mv {} {}/{}".format(filename, malware_path, os.path.basename(filename))], shell=True)
              PID = proc.pid
              proc.wait()

            for f in glob.glob("{}/*.log".format(path)):
              os.remove(f)

        except Exception as e:
            print("Something wrong here, file {}, exc {}".format(filename, e))
            if PID:
                proc.terminate()
            raise

except (KeyboardInterrupt, SystemExit):
    print("From lol: interrupt received, stopping...")
    sys.exit(-1)
