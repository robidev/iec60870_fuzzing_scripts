#!/usr/bin/env python3
# Designed for use with boofuzz v0.0.8
from boofuzz import *
from subprocess import Popen, PIPE
import signal
import sys


def signal_handler(sig, frame):
        global p
        print('You pressed Ctrl+C!')
        p.kill()
        sys.exit(0)

def main():
    """
    This example is a very simple 104 fuzzer. It uses no process monitory
    (procmon) and assumes that the 104 server is already running.
    """
    global p
    signal.signal(signal.SIGINT, signal_handler)
    p = Popen(["python3","process_monitor_unix.py","-P 26002"])

    start_cmd = ["../simple_server_orig"]
    stop_cmd = ["pkill","simple_server_orig"]
    session = Session(
        target=Target(
            connection=SocketConnection("10.84.134.10", 2404, proto='tcp'),
            #procmon=pedrpc.Client("127.0.0.1", 26002),
            #procmon_options={
            #  "start_commands": [start_cmd],
            #  "stop_commands": [stop_cmd],
            #  "proc_name": "simple_server",
            #},
        ),
        #sleep_time=1,
    )

    s_initialize("startdt")
    s_byte(0x68) # start
    s_byte(0x04) # len
    s_byte(0x07) # c1 lsb
    s_byte(0x00) #    msb
    s_byte(0x00) # c2 lsb
    s_byte(0x00) #    msb


    s_initialize("stopdt")
    s_byte(0x68) # start
    s_byte(0x04) # len
    s_byte(0x13) # c1
    s_byte(0x00) #
    s_byte(0x00) # c2
    s_byte(0x00) #

    s_initialize("testfr")
    s_byte(0x68) # start
    s_byte(0x04) # len
    s_byte(0x43) # c1
    s_byte(0x00) #
    s_byte(0x00) # c2
    s_byte(0x00) #

    s_initialize("GI")
    s_byte(0x68) # start
    s_byte(0x0e) # len
    s_byte(0x00) # c1
    s_byte(0x00) #
    s_byte(0x02) # c2
    s_byte(0x00) #

    s_byte(0x64) # type
    s_byte(0x01) # number of objects
    s_byte(0x06) # cause of transmission
    s_byte(0x00) # originator address
    s_word(0x0100) # ASDU field address
    s_byte(0x00) # obj address
    s_byte(0x00) # obj address
    s_byte(0x00) # obj address
    s_byte(0x14) # GI

    session.connect(s_get("startdt"))
    session.connect(s_get("startdt"), s_get("stopdt"))

    session.connect(s_get("startdt"), s_get("testfr"))
    session.connect(s_get("testfr"), s_get("stopdt"))

    session.connect(s_get("startdt"), s_get("GI"))
    session.connect(s_get("GI"), s_get("stopdt"))
    
    session.fuzz()


if __name__ == "__main__":
    main()