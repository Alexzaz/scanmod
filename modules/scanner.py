import nmap3
from dataclasses import dataclass
from re import match as rematch
from enum import Enum
from multiprocessing import Process
from time import sleep, time
from datetime import datetime

from nmap import PortScanner
from rich import box
from rich.table import Table

from modules.logger import banner
from modules.utils import GetIpAdress, ScanMode, ScanType, is_root

"""modify ADD CONNECT TO CH"""
#import clickhouse_connect as ChConnect


"""add function for regular express"""
def is_ip(str_):
    return bool(rematch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str_))


@dataclass()
class TargetInfo:
    mac: str = "Unknown"
    vendor: str = "Unknown"
    os: str = "Unknown"
    os_accuracy: int = 0
    os_type: str = "Unknown"

    def colored(self) -> str:

        return (
            f"[yellow]MAC Address :[/yellow] {self.mac}\n"
            + f"[yellow]Vendor :[/yellow] {self.vendor}\n"
            + f"[yellow]OS :[/yellow] {self.os}\n"
            + f"[yellow]Accuracy :[/yellow] {self.os_accuracy}\n"
            + f"[yellow]Type :[/yellow] {self.os_type[:20]}\n"
        )

    def __str__(self) -> str:
        return (
            f"MAC Address : {self.mac}"
            + f" Vendor : {self.vendor}\n"
            + f"OS : {self.os}"
            + f" Accuracy : {self.os_accuracy}"
            + f" Type : {self.os_type}"
            + "\n"
        )


# do a ping scan using nmap
def TestPing(target, mode=ScanMode.Normal) -> list:
    nm = PortScanner()
    if isinstance(target, list):
        target = " ".join(target)
    if mode == ScanMode.Evade and is_root():
        nm.scan(hosts=target, arguments="-sn -T 2 -f -g 53 --data-length 10")
    else:
        nm.scan(hosts=target, arguments="-sn")

    return nm.all_hosts()


# do a arp scan using nmap
def TestArp(target, mode=ScanMode.Normal) -> list:
    nm = PortScanner()
    nm3 = nmap3.NmapHostDiscovery()
    hosts = []
    if isinstance(target, list):
        target = " ".join(target)
    if mode == ScanMode.Evade:
        nm.scan(hosts=target, arguments="-sn -PR -T 2 -f -g 53 --data-length 10")
    else:
        resultofdiscovery = nm3.nmap_arp_discovery("192.168.15.17/24")
        for key in resultofdiscovery.keys():
            if is_ip(key) and resultofdiscovery[key]['state']['state'] == "up":
                hosts.append(key)
        #nm.scan(hosts=target, arguments="-sn -PR")

    return hosts


# run a port scan on target using nmap
def PortScan(
    target,
    log,
    ChClient,
    insertDate,
    idScan,
    scanspeed=5,
    host_timeout=240,
    mode=ScanMode.Normal,
    customflags=""
) -> list:

    log.logger("info", f"Scanning {target} for open ports ...")

    if (time() - insertDate) > 30:
        insertDate = time()
        print("change time")
        ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                        datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                        "\' where idScan = " + str(idScan)
                        )
    nm = PortScanner()
    nm3 = nmap3.Nmap()
    targetinfo = []
    try:
        if is_root():
            if mode == ScanMode.Evade:
                nm.scan(
                    hosts=target,
                    arguments=" ".join(
                        [
                            "-sS",
                            "-sV",
                            "-O",
                            "-Pn",
                            "-T",
                            "2",
                            "-f",
                            "-g",
                            "53",
                            "--data-length",
                            "10",
                            customflags,
                        ]
                    ),
                )
            else:
                print(target)
                targetinfo = nm3.nmap_version_detection(target, args = "-O")
                """nm.scan(
                    hosts=target,
                    arguments=" ".join(
                        [
                            "-sS",
                            "-sV",
                            "--host-timeout",
                            str(host_timeout),
                            "-Pn",
                            "-O",
                            "-T",
                            str(scanspeed),
                            customflags,
                        ]
                    ),
                )"""
        else:
            nm.scan(
                hosts=target,
                arguments=" ".join(
                    [
                        "-sV",
                        "--host-timeout",
                        str(host_timeout),
                        "-Pn",
                        "-T",
                        str(scanspeed),
                        customflags,
                    ]
                ),
            )
        if (time() - insertDate) > 30:
            insertDate = time()
            print("change time")
            ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                            datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                            "\' where idScan = " + str(idScan)
                            )
    except Exception as e:
        if (time() - insertDate) > 30:
            insertDate = time()
            print("change time")
            ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                            datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                            "\', nStatus = " + '2' +\
                            ", cStatusDescription = \'Ошибка при сканировании узла " + target +\
                            "\' where idScan = " + str(idScan)
                            )
        raise SystemExit(f"Error: {e}")
    else:
        if (time() - insertDate) > 30:
            insertDate = time()
            print("change time")
            ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                            datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                            "\' where idScan = " + str(idScan)
                            )
        return targetinfo


def CreateNoise(target) -> None:
    nm = PortScanner()
    while True:
        try:
            if is_root():
                nm.scan(hosts=target, arguments="-A -T 5 -D RND:10")
            else:
                nm.scan(hosts=target, arguments="-A -T 5")
        except KeyboardInterrupt:
            raise SystemExit("Ctr+C, aborting.")
        else:
            break


def NoiseScan(target, log, console, scantype=ScanType.ARP, noisetimeout=None) -> None:
    banner("Creating noise...", "green", console)

    Uphosts = TestPing(target)
    if scantype == ScanType.ARP:
        if is_root():
            Uphosts = TestArp(target)

    try:
        with console.status("Creating noise ...", spinner="line"):
            NoisyProcesses = []
            for host in Uphosts:
                log.logger("info", f"Started creating noise on {host}...")
                P = Process(target=CreateNoise, args=(host,))
                NoisyProcesses.append(P)
                P.start()
                if noisetimeout:
                    sleep(noisetimeout)
                else:
                    while True:
                        sleep(1)

        log.logger("info", "Noise scan complete!")
        for P in NoisyProcesses:
            P.terminate()
        raise SystemExit
    except KeyboardInterrupt:
        log.logger("error", "Noise scan interrupted!")
        raise SystemExit


def DiscoverHosts(target, console, scantype=ScanType.ARP, mode=ScanMode.Normal) -> list:
    if isinstance(target, list):
        banner(
            f"Scanning {len(target)} target(s) using {scantype.name} scan ...",
            "green",
            console,
        )
    else:
        banner(f"Scanning {target} using {scantype.name} scan ...", "green", console)

    if scantype == ScanType.ARP:
        OnlineHosts = TestArp(target, mode)
    else:
        OnlineHosts = TestPing(target, mode)

    return OnlineHosts


def InitHostInfo(target_key) -> TargetInfo:
    try:
        mac = target_key["macaddress"]["addr"]
    except (KeyError, IndexError, TypeError):
        mac = "Unknown"

    try:
        vendor = target_key["osmatch"][0]["osclass"]["vendor"]
    except (KeyError, IndexError):
        vendor = "Unknown"

    try:
        os = target_key["osmatch"][0]["name"]
    except (KeyError, IndexError):
        os = "Unknown"

    try:
        os_accuracy = target_key["osmatch"][0]["accuracy"]
    except (KeyError, IndexError):
        os_accuracy = "Unknown"

    try:
        os_type = target_key["osmatch"][0]["osclass"]["type"]
    except (KeyError, IndexError):
        os_type = "Unknown"

    return TargetInfo(
        mac=mac,
        vendor=vendor,
        os=os,
        os_accuracy=os_accuracy,
        os_type=os_type,
    )


def InitPortInfo(port):
    state = "Unknown"
    service = "Unknown"
    product = "Unknown"
    version = "Unknown"
    protocol = "Unknown"
    cpe = "Unknown"

    if not len(port["state"]) == 0:
        state = port["state"]

    if not len(port["service"]["name"]) == 0:
        service = port["service"]["name"]

    if "product" in port["service"] and len(port["service"]["product"]) != 0:
        product = port["service"]["product"]

    if "version" in port["service"] and len(port["service"]["version"]) != 0:
        version = port["service"]["version"]
    
    if not len(port["protocol"]) == 0:
        protocol = port["protocol"]

    if len(port["cpe"]) != 0 and len(port["cpe"][0]["cpe"]) != 0: 
        cpe = port["cpe"][0]["cpe"][5:]
        if len(cpe.split(':')) == 3 and version != "Unknown":
            cpe = cpe + ":" + version.split()[0]

    print(state, service, product, version, protocol, cpe)

    return state, service, product, version, protocol, cpe


def AnalyseScanResults(nm, log, console, idScan, insertDate,  atomicInsert, ChClient, target=None) -> list:
    """
    Analyse and print scan results.
    """
    HostArray = []
    if target is None:
        target = nm.all_hosts()[0]

    try:
        nm[target]
    except KeyError:
        log.logger("warning", f"Target {target} seems to be offline.")
        return []

    CurrentTargetInfo = InitHostInfo(nm[target])
    atomicInsert['cIPv4'] = target
    atomicInsert['nIPFlag'] = 0
    atomicInsert['cMac'] = CurrentTargetInfo.mac
    atomicInsert['cHostname'] = ''
    atomicInsert['cOSName'] = CurrentTargetInfo.os
    atomicInsert['nStatus'] = 0
    

    if is_root():
        if nm[target]["state"]["reason"] in ["localhost-response", "user-set"]:
            log.logger("info", f"Target {target} seems to be us.")
    elif GetIpAdress() == target:
        log.logger("info", f"Target {target} seems to be us.")

    if len(nm[target]['ports']) == 0:
        log.logger("warning", f"Target {target} seems to have no open ports.")
        return HostArray

    banner(f"Portscan results for {target}", "green", console)

    if not CurrentTargetInfo.mac == "Unknown" and not CurrentTargetInfo.os == "Unknown":
        console.print(CurrentTargetInfo.colored(), justify="center")

    table = Table(box=box.MINIMAL)

    table.add_column("Port", style="cyan")
    table.add_column("State", style="white")
    table.add_column("Service", style="blue")
    table.add_column("Product", style="red")
    table.add_column("Version", style="purple")

    for port in nm[target]['ports']:
        if (time() - insertDate) > 30:
            insertDate = time()
            print("change time")
            ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                            datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                            "\' where idScan = " + str(idScan)
                            )
        state, service, product, version, protocol, cpe = InitPortInfo(port)
        atomicInsert['ports'][str(port["portid"])] = {
            'cService': service,
            'cBanner': str(product),
            'cVersion': version,
            'cTransProto': protocol
        }
        table.add_row(str(port["portid"]), state, service, product, version)

        if state == "open":
            HostArray.insert(len(HostArray), [target, int(port["portid"]), service, product, version, cpe])

    console.print(table, justify="center")

    return HostArray
