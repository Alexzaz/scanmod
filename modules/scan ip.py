try:
    from os import getuid

    import distro
except ImportError:
    from ctypes import windll

from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime
from enum import Enum
from os import get_terminal_size
from platform import platform, system
from re import search
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import DEVNULL, PIPE, CalledProcessError, Popen, check_call
from sys import platform as sys_platform

from requests import get
from rich.text import Text


def GetIpAdress() -> str:
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    PrivateIPAdress = s.getsockname()[0]
    print(PrivateIPAdress)
    return PrivateIPAdress


def DetectIPRange() -> str:
    net_dict = {
        "255.255.255.255": 32,
        "255.255.255.254": 31,
        "255.255.255.252": 30,
        "255.255.255.248": 29,
        "255.255.255.240": 28,
        "255.255.255.224": 27,
        "255.255.255.192": 26,
        "255.255.255.128": 25,
        "255.255.255.0": 24,
        "255.255.254.0": 23,
        "255.255.252.0": 22,
        "255.255.248.0": 21,
        "255.255.240.0": 20,
        "255.255.224.0": 19,
        "255.255.192.0": 18,
        "255.255.128.0": 17,
        "255.255.0.0": 16,
    }
    ip = GetIpAdress()
    if system().lower() == "windows":
        proc = Popen("ipconfig", stdout=PIPE)
        while True:
            line = proc.stdout.readline()
            if ip.encode() in line:
                break
        mask = (
            proc.stdout.readline().rstrip().split(b":")[-1].replace(b" ", b"").decode()
        )
        net_range = f"{ip}/{net_dict[mask]}"
    else:
        proc = Popen(["ip", "-o", "-f", "inet", "addr", "show"], stdout=PIPE)
        regex = f"\\b{ip}\/\\b([0-9]|[12][0-9]|3[0-2])\\b"
        cmd_output = proc.stdout.read().decode()
        net_range = search(regex, cmd_output).group()
        print(net_range)
    return net_range



if __name__=='__main__':
    DetectIPRange()