from datetime import datetime, timedelta, timezone
from time import time, sleep

import asyncio, nmap3

from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import AnalyseScanResults, DiscoverHosts, NoiseScan, PortScan, TestArp
from modules.searchvuln import SearchSploits
from modules.utils import (
    DetectIPRange,
    InitArgsAPI,
    InitArgsConf,
    InitArgsMode,
    InitArgsScanType,
    InitArgsTarget,
    InitAutomation,
    InitReport,
    UserConfirmation,
    cli,
)
from modules.web.webvuln import webvuln


from re import match


"""modify ADD CONNECT TO CH"""
import clickhouse_connect as ChConnect


DAYDICT = {
    "mo": 1,
    "tu": 2,
    "we": 3,
    "th": 4,
    "fr": 5,
    "sa": 6,
    "su": 7
}


async def scanpool(taskarray):
    tasksarray = {}
    resultdict = {}
    nm3 = nmap3.NmapScanTechniquesAsync()
    for host in taskarray:
        #print("create task " + host + "\n")
        tasksarray[host] = asyncio.create_task(nm3.nmap_udp_scan(host, args = "-O -sSV --defeat-icmp-ratelimit"))
    all_tasks = asyncio.all_tasks()
    current_task = asyncio.current_task()
    #print(current_task)
    all_tasks.remove(current_task)
    await asyncio.wait(all_tasks)

    for host in taskarray:
        #print("save results " + host + "\n")
        resultdict[host] = tasksarray[host].result()

    return resultdict




def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, console, console2, log, ChClient, idScan_, insertDate_
) -> None:



    #ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    #ScanWeb = WebScan()
    

    scancomplete = False
    scannedHosts = 0

    while not scancomplete:
        countofpool = 0
        result = False
        lastscan = False
        targetarray = []
        while countofpool < 10 and scannedHosts < len(targetarg):
            #print("add host " + targetarg[scannedHosts] + "\n")
            targetarray.append(targetarg[scannedHosts])
            countofpool += 1
            scannedHosts += 1
        if scannedHosts == len(targetarg):
            lastscan = True
            #print("lastscan")
        if scannedHosts < len(targetarg) + 1:
            #print("asyncio part\n")
            result = asyncio.run(scanpool(targetarray))
            if result != False:
                for host in targetarray:
                    #print(targetarray)
                    atomicInsert = {'aboutHost': {'ports': {}}, 'CVEofHost': {}}
                    AnalyseScanResults(result[host], log, console, idScan_, insertDate_, atomicInsert['aboutHost'], ChClient, host)
                    if (time() - insertDate_) > 30:
                        insertDate_ = time()
                        #print("change time")
                        ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                                        datetime.fromtimestamp(insertDate_ + 20*60).strftime("%Y-%m-%d %H:%M:%S") +\
                                        "\' where idScan = " + str(idScan_)
                                        )
                    insertTime_ = datetime.now()
                    dataInsert = [[idScan_,\
                                        insertTime_,\
                                        host,\
                                        atomicInsert['aboutHost']['nIPFlag'],\
                                        atomicInsert['aboutHost']['cMac'],\
                                        0,\
                                        '',\
                                        '',\
                                        '',\
                                        '',\
                                        '',\
                                        '',\
                                        '',\
                                        atomicInsert['aboutHost']['cHostname'],\
                                        atomicInsert['aboutHost']['cOSName'],\
                                        atomicInsert['aboutHost']['nStatus']]]
                    for port_ in atomicInsert['aboutHost']['ports'].keys():
                        addingPort = [
                                idScan_,\
                                insertTime_,\
                                host,\
                                atomicInsert['aboutHost']['nIPFlag'],\
                                '',\
                                int(port_),\
                                atomicInsert['aboutHost']['ports'][port_]['cTransProto'],\
                                atomicInsert['aboutHost']['ports'][port_]['cBanner'],\
                                atomicInsert['aboutHost']['ports'][port_]['cService'],\
                                atomicInsert['aboutHost']['ports'][port_]['cVersion'],\
                                '',\
                                '',\
                                '',\
                                '',\
                                '',\
                                0
                            ]
                        dataInsert.append(addingPort)
                    column_names_ = ["idScan",\
                                        "dtInsertTime",\
                                        "cIPv4",\
                                        "nIPFlag",\
                                        "cMac",\
                                        "nPort",\
                                        "cTransProto",\
                                        "cBanner",\
                                        "cService",\
                                        "cVersion",\
                                        "cCVEid",\
                                        "cCVESeverity",\
                                        "cCVEName",\
                                        "cHostname",\
                                        "cOSName",\
                                        "nStatus"
                                    ]
                    column_type_names_ = [\
                                            'UInt64',\
                                            'DateTime',\
                                            'IPv4',\
                                            'UInt8',\
                                            'String',\
                                            'UInt16',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'String',\
                                            'UInt16'
                                        ]
                    """if ScanVulns and len(PortArray) > 0:
                        VulnsArray = SearchSploits(PortArray, log, console, console2, idScan, insertDate, atomicInsert, ChClient, apiKey)
                        #if DownloadExploits and len(VulnsArray) > 0:
                            #GetExploitsFromArray(VulnsArray, log, console, console2, host)
                        for CVE_ID in atomicInsert['CVEofHost'].keys():
                            addingCve = [
                                idScan,\
                                insertTime_,\
                                atomicInsert['CVEofHost'][CVE_ID]['cIPv4'],\
                                atomicInsert['CVEofHost'][CVE_ID]['nIPFlag'],\
                                '',\
                                atomicInsert['CVEofHost'][CVE_ID]['cPort'],\
                                atomicInsert['CVEofHost'][CVE_ID]['cTransProto'],\
                                atomicInsert['CVEofHost'][CVE_ID]['cBanner'],\
                                atomicInsert['CVEofHost'][CVE_ID]['cService'],\
                                atomicInsert['CVEofHost'][CVE_ID]['cVersion'],\
                                CVE_ID,\
                                atomicInsert['CVEofHost'][CVE_ID]['cCVESeverity'],\
                                atomicInsert['CVEofHost'][CVE_ID]['cCVEName'],\
                                '',\
                                '',\
                                0
                            ]
                            dataInsert.append(addingCve)"""
                    ChClient.insert(\
                        table="tScanData",\
                        data = dataInsert,\
                        column_names = column_names_,\
                        column_type_names = column_type_names_,\
                        )
                    if lastscan:
                        scancomplete = True
                ipScanned = int(ChClient.command("select nIPScanned from tScanHistory where idScan = " + str(idScan_)))
                #print("\n"+str(ipScanned)+"\n")
                ChClient.command("alter table stet.tScanHistory update nIPScanned = " +\
                                str(ipScanned + len(targetarray)) +\
                                " where idScan = " + str(idScan_)
                                )
        else:
            scancomplete = True


    """for host in targetarg:
        if ScanPorts:
            atomicInsert = {'aboutHost': {'ports': {}}, 'CVEofHost': {}}
            PortScanResults = PortScan(
                host, log, ChClient, insertDate, idScan, args.speed, args.host_timeout, scanmode, args.nmap_flags
            )
            #print(host)
            PortArray = AnalyseScanResults(PortScanResults, log, console, idScan, insertDate, atomicInsert['aboutHost'], ChClient, host)
            if (time() - insertDate) > 30:
                insertDate = time()
                #print("change time")
                ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                                datetime.fromtimestamp(insertDate + 20*60).strftime("%Y-%m-%d %H:%M:%S") +\
                                "\' where idScan = " + str(idScan)
                                )
            insertTime_ = datetime.now()
            dataInsert = [[idScan,\
                                insertTime_,\
                                host,\
                                atomicInsert['aboutHost']['nIPFlag'],\
                                atomicInsert['aboutHost']['cMac'],\
                                0,\
                                '',\
                                '',\
                                '',\
                                '',\
                                '',\
                                '',\
                                '',\
                                atomicInsert['aboutHost']['cHostname'],\
                                atomicInsert['aboutHost']['cOSName'],\
                                atomicInsert['aboutHost']['nStatus']]]
            for port_ in atomicInsert['aboutHost']['ports'].keys():
                addingPort = [
                        idScan,\
                        insertTime_,\
                        host,\
                        atomicInsert['aboutHost']['nIPFlag'],\
                        '',\
                        int(port_),\
                        atomicInsert['aboutHost']['ports'][port_]['cTransProto'],\
                        atomicInsert['aboutHost']['ports'][port_]['cBanner'],\
                        atomicInsert['aboutHost']['ports'][port_]['cService'],\
                        atomicInsert['aboutHost']['ports'][port_]['cVersion'],\
                        '',\
                        '',\
                        '',\
                        '',\
                        '',\
                        0
                    ]
                dataInsert.append(addingPort)
            column_names_ = ["idScan",\
                                "dtInsertTime",\
                                "cIPv4",\
                                "nIPFlag",\
                                "cMac",\
                                "nPort",\
                                "cTransProto",\
                                "cBanner",\
                                "cService",\
                                "cVersion",\
                                "cCVEid",\
                                "cCVESeverity",\
                                "cCVEName",\
                                "cHostname",\
                                "cOSName",\
                                "nStatus"
                            ]
            column_type_names_ = [\
                                    'UInt64',\
                                    'DateTime',\
                                    'IPv4',\
                                    'UInt8',\
                                    'String',\
                                    'UInt16',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'String',\
                                    'UInt16'
                                ]
            if ScanVulns and len(PortArray) > 0:
                VulnsArray = SearchSploits(PortArray, log, console, console2, idScan, insertDate, atomicInsert, ChClient, apiKey)
                #if DownloadExploits and len(VulnsArray) > 0:
                    #GetExploitsFromArray(VulnsArray, log, console, console2, host)
                for CVE_ID in atomicInsert['CVEofHost'].keys():
                    addingCve = [
                        idScan,\
                        insertTime_,\
                        atomicInsert['CVEofHost'][CVE_ID]['cIPv4'],\
                        atomicInsert['CVEofHost'][CVE_ID]['nIPFlag'],\
                        '',\
                        atomicInsert['CVEofHost'][CVE_ID]['cPort'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cTransProto'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cBanner'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cService'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cVersion'],\
                        CVE_ID,\
                        atomicInsert['CVEofHost'][CVE_ID]['cCVESeverity'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cCVEName'],\
                        '',\
                        '',\
                        0
                    ]
                    dataInsert.append(addingCve)
            ChClient.insert(\
                table="tScanData",\
                data = dataInsert,\
                column_names = column_names_,\
                column_type_names = column_type_names_,\
                )
            ipScanned = int(ChClient.command("select nIPScanned from tScanHistory where idScan = " + str(idScan)))
            ChClient.command("alter table stet.tScanHistory update nIPScanned = " +\
                            str(ipScanned + 1) +\
                            " where idScan = " + str(idScan)
                            )
                

        if ScanWeb:
            webvuln(host, log, console)

    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )"""
    ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                            datetime.fromtimestamp(time()).strftime("%Y-%m-%d %H:%M:%S") +\
                            "\', nStatus = " + '0' +\
                            ", cStatusDescription = \'Сканирование завершено без ошибок\'" +\
                            " where idScan = " + str(idScan_)
                            )



def main():
    global args
    global timezonecurrent
    currtime = datetime.now(tz = timezonecurrent)
    #args = cli()
    if args.no_color:
        console = Console(record=True, color_system=None)
        console2 = Console(record=False, color_system=None)
    else:
        console = Console(record=True, color_system="truecolor")
        console2 = Console(record=False, color_system="truecolor")

    if args.version:
        #print(f"AutoPWN Suite v{__version__}")
        raise SystemExit

    #print_banner(console)
    #check_version(__version__, log)

    

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    apiKey = InitArgsAPI(args, log)
    ReportMethod, ReportObject = InitReport(args, log)


    ChClient = ChConnect.create_client(host = args.databaseaddress, interface = args.databaseinterface, port = args.databaseport, database = args.databasename, client_name = args.databaseuser)
    targets = []
    ipAll = 0
    insertDate = 0
    idScan = 0
    if len(targetarg) != 0:
        for i in range(len(targetarg)):
            targetarg[i] = targetarg[i].strip()
            if targetarg[i].find("/") != -1:
                ipAll = ipAll + 2**(32 - int(targetarg[i].split("/")[1]))
            elif targetarg[i].find("-") != -1 or targetarg[i].find(",") != -1:
                sumips = 1
                for ipdiap in targetarg[i].strip().split("."):
                    tmpsum = 0
                    for tmpdiap in ipdiap.strip().split(","):
                        if tmpdiap.find("-") != -1:
                            tmpsum += int(tmpdiap.split("-")[1].strip()) - int(tmpdiap.split("-")[0].strip()) + 1
                        else:
                            tmpsum += 1
                    sumips = sumips * tmpsum
                ipAll = ipAll + sumips
            elif match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' ,targetarg[i]) is not None:
                ipAll = ipAll + 1

        idScan = int(ChClient.command("select max(idScan) from tScanHistory"))
        if idScan == 0:
            idScan = 1
        else:
            idScan += 1
        insertDate = time() + 60*60
        #print(targets)
        dataInsert = [[\
                        idScan,\
                        datetime.fromtimestamp(insertDate - 60*60),\
                        datetime.fromtimestamp(insertDate),\
                        "; ".join(targetarg).strip(),\
                        0,\
                        ipAll,\
                        1,\
                        "Сканирование в процессе"\
                        ]]
        column_names_ = ["idScan",\
                            "dtStartTime",\
                            "dtEndTime",\
                            "cNetworks",\
                            "nIPScanned",\
                            "nIPAll",\
                            "nStatus",\
                            "cStatusDescription"\
                        ]
        ChClient.insert(\
                        table="tScanHistory",\
                        data = dataInsert,\
                        column_names = column_names_,\
                        column_type_names = ['UInt64', 'DateTime', 'DateTime', 'String', 'UInt32', 'UInt32' ,'UInt8', 'String'],\
                        )


        #Анализ заданных подсетей на обнаружение хостов
        for i in range(len(targetarg)):
            if targetarg[i].find("/") != -1:
                targetstmp = TestArp(targetarg[i])
                targets = targets + targetstmp
            elif targetarg[i].find("-") != -1:
                targetstmp = TestArp(targetarg[i])
                targets = targets + targetstmp
            elif match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' ,targetarg[i]) is not None:
                targets.append(targetarg[i])
    else:
        idScan = int(ChClient.command("select max(idScan) from tScanHistory"))
        if idScan == 0:
            idScan = 1
        else:
            idScan += 1
        insertDate = time() + 60*60
        #print(targets)
        dataInsert = [[\
                        idScan,\
                        datetime.fromtimestamp(insertDate - 60*60),\
                        datetime.fromtimestamp(insertDate),\
                        "; ".join(targetarg).strip(),\
                        0,\
                        ipAll,\
                        1,\
                        "Сканирование в процессе"\
                        ]]
        column_names_ = ["idScan",\
                            "dtStartTime",\
                            "dtEndTime",\
                            "cNetworks",\
                            "nIPScanned",\
                            "nIPAll",\
                            "nStatus",\
                            "cStatusDescription"\
                        ]
        ChClient.insert(\
                        table="tScanHistory",\
                        data = dataInsert,\
                        column_names = column_names_,\
                        column_type_names = ['UInt64', 'DateTime', 'DateTime', 'String', 'UInt32', 'UInt32' ,'UInt8', 'String'],\
                        )
        targets = DetectIPRange()
        targets = DiscoverHosts(targets, console, scantype, scanmode)
        ChClient.command("alter table stet.tScanHistory update nIPAll = \'" +\
                            len(targets) +\
                            " where idScan = " + str(idScan)
                            )

    #ParamPrint(args, targetarg, scantype, scanmode, apiKey, console, log)
    #print(targets)
    #print("\nTargets list ^^\n")
    StartScanning(args, targets, scantype, scanmode, apiKey, console, console2, log, ChClient, idScan, insertDate)

    return [currtime, datetime.now(tz = timezonecurrent)]

    #InitializeReport(ReportMethod, ReportObject, log, console)
    #SaveOutput(console, args.output_type, args.report, args.output)


if __name__ == "__main__":
    log = Logger()
    while 1:
        args = cli()
        #print(args.config)
        if args.config:
            InitArgsConf(args, log)
        needscan = False
        timezonecurrent = args.timezone
        if timezonecurrent[0] == "+":
            timezonecurrent = timezone(+timedelta(hours = int(timezonecurrent[1:])))
        elif timezonecurrent[0] == "-":
            timezonecurrent = timezone(-timedelta(hours = int(timezonecurrent[1:])))
        sleep_seconds = 0
        shedulescan = args.shedulescan
        shedulescan = shedulescan.split(";")
        currentdate = datetime.now(tz = timezonecurrent)
        #print(currentdate.isoformat())
        for timeofscan in shedulescan:
            timeofscan = timeofscan.strip().split()
            if timeofscan[0] == "*" and currentdate.hour == int(timeofscan[1].split(":")[0]) and currentdate.minute == int(timeofscan[1].split(":")[1]):
                needscan = True
                break
            elif timeofscan[0] != "*":
                if timeofscan[0].find("-") != -1:
                    dayperiod = timeofscan[0].strip().split("-")
                    for dayvalue in range(DAYDICT[dayperiod[0].lower()], DAYDICT[dayperiod[1].lower()] + 1):
                        if dayvalue == currentdate.isoweekday() and currentdate.hour == int(timeofscan[1].split(":")[0]) and currentdate.minute == int(timeofscan[1].split(":")[1]):
                            needscan = True
                            break
                else:
                    for dayvalue in timeofscan[0].strip().split(","):
                        if DAYDICT[dayvalue.lower()] == currentdate.isoweekday() and currentdate.hour == int(timeofscan[1].split(":")[0]) and currentdate.minute == int(timeofscan[1].split(":")[1]):
                            needscan = True
                            break
                if needscan:
                    break
        if needscan:
            try:
                main()
            except KeyboardInterrupt:
                raise SystemExit("Ctrl+C pressed. Exiting.")
        sleep(60)
