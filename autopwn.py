from datetime import datetime, timedelta

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
    insertDate = datetime.now()
    dataInsert = [[\
                    idScan,\
                    insertDate.strftime("%b %d %Y %H:%M:%S"),\
                    (insertDate + timedelta(seconds = 10)).strftime("%b %d %Y %H:%M:%S"),\
                    [targetarg],\
                    1,\
                    "Сканирование в процессе"\
                    ]]
    ChClient.insert(\
                    table="tScanHistory",\
                    data = dataInsert,\
                    column_names = "idScan, dtStartTime, dtEndTime, cNetworks, nStatus, cStatusDescription",\
                    column_type_names = ['UInt64', 'DateTime', 'DateTime', 'Array(String)', 'UInt8', 'String'],\
                    column_oriented = True,\
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
            atomicInsert = {'aboutHost': {}, 'CVEofHost': {}}
            PortScanResults = PortScan(
                host, log, args.speed, args.host_timeout, scanmode, args.nmap_flags
            )
            PortArray = AnalyseScanResults(PortScanResults, log, console, idScan, atomicInsert.aboutHost, host)
            if ScanVulns and len(PortArray) > 0:
                VulnsArray = SearchSploits(PortArray, log, console, console2, idScan, atomicInsert.CVEofHost, ChClient, apiKey)
                if DownloadExploits and len(VulnsArray) > 0:
                    GetExploitsFromArray(VulnsArray, log, console, console2, host)
                insertTime = datetime.now().strftime("%b %d %Y %H:%M:%S")
                dataInsert = [[idScan,\
                                insertTime,\
                                atomicInsert['aboutHost']['cIPv4'],\
                                atomicInsert['aboutHost']['nIPFlag'],\
                                atomicInsert['aboutHost']['cMac'],\
                                None,\
                                None,\
                                None,\
                                None,\
                                None,\
                                None,\
                                None,\
                                None,\
                                atomicInsert['aboutHost']['cHostname'],\
                                atomicInsert['aboutHost']['cOSName'],\
                                atomicInsert['aboutHost']['nStatus']]]
                column_names_ = "idScan,\
                                    dtInsertTime,\
                                    cIPv4,\
                                    nIPFlag,\
                                    cMac,\
                                    nPort,\
                                    cTransProto,\
                                    cBanner,\
                                    cService,\
                                    cVersion,\
                                    cCVEid,\
                                    cCVESeverity,\
                                    cCVEName,\
                                    cHostname,\
                                    cOSName,\
                                    nStatus"
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
                for CVE_ID in atomicInsert['CVEofHost'].keys():
                    addingCve = [
                        idScan,\
                        insertTime,\
                        atomicInsert['CVEofHost'][CVE_ID]['cIPv4'],\
                        atomicInsert['CVEofHost'][CVE_ID]['nIPFlag'],\
                        None,\
                        atomicInsert['CVEofHost'][CVE_ID]['cPort'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cTransProto'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cBanner'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cService'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cVersion'],\
                        CVE_ID,\
                        atomicInsert['CVEofHost'][CVE_ID]['cCVESeverity'],\
                        atomicInsert['CVEofHost'][CVE_ID]['cCVEName'],\
                        None,\
                        None,\
                        0
                    ]
                    dataInsert.append(addingCve)
                ChClient.insert(\
                    table="tScanData",\
                    data = dataInsert,\
                    column_names = column_names_,\
                    column_type_names = column_type_names_,\
                    column_oriented = True,\
                    )
                

        if ScanWeb:
            webvuln(host, log, console)

    """need rework console.print(
        "{time} - Scan completed.".format(
            time=datetime.now().strftime("%b %d %Y %H:%M:%S")
        )
    )"""



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

    """if args.version:
        print(f"AutoPWN Suite v{__version__}")
        raise SystemExit"""

    #print_banner(console)
    check_version(__version__, log)

    if args.config:
        InitArgsConf(args, log)

    InitAutomation(args)
    targetarg = InitArgsTarget(args, log)
    scantype = InitArgsScanType(args, log)
    scanmode = InitArgsMode(args, log)
    apiKey = InitArgsAPI(args, log)
    ReportMethod, ReportObject = InitReport(args, log)

    #ParamPrint(args, targetarg, scantype, scanmode, apiKey, console, log)

    StartScanning(args, targetarg, scantype, scanmode, apiKey, console, console2, log)

    InitializeReport(ReportMethod, ReportObject, log, console)
    SaveOutput(console, args.output_type, args.report, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Ctrl+C pressed. Exiting.")
