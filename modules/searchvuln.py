from dataclasses import dataclass
from textwrap import wrap
from time import time
from datetime import datetime

from modules.logger import banner
from modules.nist_search import searchCVE
from modules.utils import CheckConnection, get_terminal_width
from rich.progress_bar import ProgressBar

"""modify ADD CONNECT TO CH"""
#import clickhouse_connect as ChConnect

@dataclass
class VulnerableSoftware:
    title: str
    CVEs: list


def GenerateKeyword(product: str, version: str, service: str):
    if product.lower().rstrip() == "unknown":
        product = ""

    if version.lower().rstrip() == "unknown":
        version = ""

    if service.lower().rstrip() == "unknown":
        service = ""

    keyword = [""]
    dontsearch = [
        "ssh",
        "vnc",
        "http",
        "https",
        "ftp",
        "sftp",
        "smtp",
        "smb",
        "smbv2",
        "linux telnetd",
        "microsoft windows rpc",
        "metasploitable root shell",
        "gnu classpath grmiregistry",
    ]

    if product.lower() not in dontsearch and product != "":
        keyword = [f"{product} {version}".rstrip(), f"{product}".rstrip()]
    elif product == "" and version != "" and service not in dontsearch and service != "":
        keyword = [f"{service} {version}".rstrip(), f"{service}".rstrip()]
    elif product == "" and version == "" and service not in dontsearch and service != "":
        keyword = [f"{service}".rstrip()]
    return keyword


def GenerateKeywords(PortArray: list) -> list:
    keywords = []
    for port in PortArray:
        product = str(port[3])
        version = str(port[4])
        service =  str(port[2])

        keyword = GenerateKeyword(product, version, service)
        if keyword[0] != "" and (keyword, str(port[1])) not in keywords:
            keywords.append((keyword, str(port[1])))

    return keywords


def SearchKeyword(keyword: tuple, log, apiKey=None) -> list:

    try:
        ApiResponseCVE = searchCVE(keyword, log, apiKey)
    except KeyboardInterrupt:
        log.logger("warning", f"Skipped vulnerability detection for {keyword}")
    except Exception as e:
        log.logger("error", e)
    else:
        return ApiResponseCVE

    return []


def SearchSploits(PortArray: list, log, console, console2, idScan, insertDate, atomicInsert, ChClient, apiKey=None) -> list:
    VulnsArray = []
    target = str(PortArray[0][0])
    term_width = get_terminal_width()

    if not CheckConnection(log):
        return []

    keywords = GenerateKeywords(PortArray)
    countPort = 0

    if len(keywords) == 0:
        log.logger("warning", f"Insufficient information for {target}")
        return []

    log.logger(
        "info", f"Searching vulnerability database for {len(keywords)} keyword(s) ..."
    )

    print(keywords)

    printed_banner = False
    with console2.status(
        "[white]Searching vulnerabilities ...[/white]", spinner="bouncingBar"
    ) as status:
        for keyword in keywords:
            print(keyword)
            if (time() - insertDate) > 30:
                insertDate = time()
                print("change time")
                ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                                datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                                "\' where idScan = " + str(idScan)
                                )
            status.start()
            status.update(
                "[white]Searching vulnerability database for[/white] "
                + f"[red]{keyword}[/red] [white]...[/white]"
            )
            for value in keyword[0]:
                if value != "":
                    ApiResponseCVE = SearchKeyword(keyword, log, apiKey)
                else:
                    ApiResponseCVE = []
            if (time() - insertDate) > 30:
                insertDate = time()
                print("change time")
                ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                                datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                                "\' where idScan = " + str(idScan)
                                )
            status.stop()
            if len(ApiResponseCVE) == 0:
                continue

            if not printed_banner:
                banner(f"Possible vulnerabilities for {target}", "red", console)
                printed_banner = True

            #console.print(f"┌─ [yellow][ {keyword} ][/yellow]")

            CVEs = []
            count_ = 0
            for CVE in ApiResponseCVE:
                if count_ < 2000:
                    if (time() - insertDate) > 30:
                        insertDate = time()
                        print("change time")
                        ChClient.command("alter table stet.tScanHistory update dtEndTime = \'" +\
                                        datetime.fromtimestamp(insertDate + 30).strftime("%Y-%m-%d %H:%M:%S") +\
                                        "\' where idScan = " + str(idScan)
                                        )
                    CVEs.append(CVE.CVEID)
                    #console.print(f"│\n├─────┤ [red]{CVE.CVEID}[/red]\n│")
                    CVEalreadyInTable = ChClient.query(
                        "select cCVEId from tScanCVE where cCVEId = \'" + CVE.CVEID + "\'",\
                        query_formats = {'String': 'string'})
                    if CVEalreadyInTable.row_count == 0:
                        dataInsert = [[
                                        str(CVE.CVEID),\
                                        '',\
                                        str(CVE.description),\
                                        str(CVE.severity)\
                                        ]]
                        ChClient.insert(\
                                        table="tScanCVE",\
                                        data = dataInsert,\
                                        column_names = ["cCVEId", "cCVEName", "cCVEDescription", "cCVESeverity"],\
                                        column_type_names = ['String', 'String', 'String', 'String']
                                        )
                    
                            
                            
                    #formatting data for CH about CVE
                    atomicInsert['CVEofHost'][CVE.CVEID] = {\
                                            'cIPv4': target,\
                                            'nIPFlag': 0,\
                                            'cPort': CVE.port,\
                                            'cTransProto': "TCP",\
                                            'cBanner': atomicInsert['aboutHost']['ports'][str(CVE.port)]['cBanner'],\
                                            'cService': atomicInsert['aboutHost']['ports'][str(CVE.port)]['cService'],\
                                            'cVersion': atomicInsert['aboutHost']['ports'][str(CVE.port)]['cVersion'],\
                                            'cCVESeverity': CVE.severity,\
                                            'cCVEName': ""
                                            }
                    

                    wrapped_description = wrap(CVE.description, term_width - 50)
                    #console.print(f"│\t\t[cyan]Description: [/cyan]")
                    #for line in wrapped_description:
                        #console.print(f"│\t\t\t{line}")
                    #console.print(
                        #f"│\t\t[cyan]Severity: [/cyan]{CVE.severity}\n"
                    #)
                    count_ += 1

            VulnObject = VulnerableSoftware(title=keyword, CVEs=CVEs)
            VulnsArray.append(VulnObject)
            countPort += 1
            #console.print("└" + "─" * (term_width - 1))

    return VulnsArray
