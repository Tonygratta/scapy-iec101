#!/usr/bin/env python3

# Authors and sources:
# https://github.com/Tonygratta/scapy-iec101

import serial
from time import time, time_ns
from iec101 import FT12Frame


def main():
    with serial.Serial("/dev/ttyS0", 9600, timeout=3) as ss:
        with open(f"iec101_{int(time())}.log", "w") as logfile:
            while True:
                try:
                    buff = ss.read(2048)
                    if len(buff) > 0:
                        ss.write(b"\xe5")
                        print(f"Received {len(buff):d} bytes:")
                        logfile.write(
                            f"{float((time_ns()//1000))/1000000:0.6f} Received: {repr(buff)}\n"
                        )
                        frame = FT12Frame(buff).show2(dump=True)
                        print(frame)
                        logfile.write(frame)
                except KeyboardInterrupt:
                    break


if __name__ == "__main__":
    main()
