from datetime import datetime
from time import time

from rich.console import Console

from modules.banners import print_banner
from modules.getexploits import GetExploitsFromArray
from modules.logger import Logger
from modules.report import InitializeReport
from modules.scanner import AnalyseScanResults, DiscoverHosts, NoiseScan, PortScan
from modules.searchvuln import SearchSploits
from modules.utils import (
    GetHostsToScan,
    InitArgsAPI,
    InitArgsConf,
    InitArgsMode,
    InitArgsScanType,
    InitArgsTarget,
    InitAutomation,
    InitReport,
    ParamPrint,
    SaveOutput,
    ScanMode,
    UserConfirmation,
    WebScan,
    check_nmap,
    cli,
    check_version,
)
from modules.web.webvuln import webvuln

"""modify ADD CONNECT TO CH"""
import clickhouse_connect as ChConnect


def StartScanning(
    args, targetarg, scantype, scanmode, apiKey, console, console2, log
) -> None:

    ChClient = ChConnect.create_client(host = "127.0.0.1", interface = "http", port = 8123, database = "stet", client_name = "SCANNER")
    idScan = int(ChClient.command("select max(idScan) from tScanHistory"))
    if idScan == 0:
        idScan = 1
    else:
        idScan += 1
    insertDate = time() + 30
    ipAll = 32 - int(targetarg.split('/')[1])
    ipAll = 2**ipAll
    dataInsert = [[\
                    idScan,\
                    datetime.fromtimestamp(insertDate - 30),\
                    datetime.fromtimestamp(insertDate),\
                    targetarg,\
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

    check_nmap(log)

    if scanmode == ScanMode.Noise:
        NoiseScan(targetarg, log, console, scantype, args.noise_timeout)

    if not args.skip_discovery:
        hosts = DiscoverHosts(targetarg, console, scantype, scanmode)
        Targets = GetHostsToScan(hosts, console)
    else:
        Targets = [targetarg]

    ScanPorts, ScanVulns, DownloadExploits = UserConfirmation()
    ScanWeb = WebScan()

    for host in Targets:
        if ScanPorts:
            atomicInsert = {'aboutHost': {'ports': {}}, 'CVEofHost': {}}
            PortScanResults = PortScan(
                host, log, ChClient, insertDate, idScan, args.speed, args.host_timeout, scanmode, args.nmap_flags
            )
            print(host)
            PortArray = AnalyseScanResults(PortScanResults, log, console, idScan, insertDate, atomicInsert['aboutHost'], ChClient, host)
            if (time() - insertDate) > 30:
                insertDate = time()
                print("change time")
                ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                                datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
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
            ipScanned = int(ChClient.command("select nIPScanned from tScanHistory where idScan = " + str(idScan)))
            ChClient.command("alter table stet.tScanHistory update nIPScanned = " +\
                            str(ipScanned + 1) +\
                            " where idScan = " + str(idScan)
                            )
                

        """if ScanWeb:
            webvuln(host, log, console)"""

    console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )
    ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                            datetime.fromtimestamp(time()).strftime("%Y-%m-%d %H:%M:%S") +\
                            "\', nStatus = " + '0' +\
                            ", cStatusDescription = \'Сканирование завершено без ошибок\'" +\
                            " where idScan = " + str(idScan)
                            )



def main() -> None:
    __author__ = "GamehunterKaan"
    __version__ = "2.1.5"

    args = cli()
    if args.no_color:
        console = Console(record=True, color_system=None)
        console2 = Console(record=False, color_system=None)
    else:
        console = Console(record=True, color_system="truecolor")
        console2 = Console(record=False, color_system="truecolor")
    log = Logger(console)

    if args.version:
        print(f"AutoPWN Suite v{__version__}")
        raise SystemExit

    print_banner(console)
    check_version(__version__, log)

    if args.config:
        InitArgsConf(args, log)

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    apiKey = InitArgsAPI(args, log)
    ReportMethod, ReportObject = InitReport(args, log)

    ParamPrint(args, targetarg, scantype, scanmode, apiKey, console, log)

    StartScanning(args, targetarg, scantype, scanmode, apiKey, console, console2, log)

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
