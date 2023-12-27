from dataclasses import dataclass
from textwrap import wrap

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


def GenerateKeyword(product: str, version: str) -> str:
    if product == "Unknown":
        product = ""

    if version == "Unknown":
        version = ""

    keyword = ""
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
        keyword = f"{product} {version}".rstrip()

    return keyword


def GenerateKeywords(PortArray: list) -> list:
    keywords = []
    for port in PortArray:
        product = str(port[3])
        version = str(port[4])

        keyword = GenerateKeyword(product, version)
        if not keyword == "" and not keyword in keywords:
            keywords.append(keyword)

    return keywords


def SearchKeyword(keyword: str, log, apiKey=None) -> list:

    try:
        ApiResponseCVE = searchCVE(keyword, log, apiKey)
    except KeyboardInterrupt:
        log.logger("warning", f"Skipped vulnerability detection for {keyword}")
    except Exception as e:
        log.logger("error", e)
    else:
        return ApiResponseCVE

    return []


def SearchSploits(PortArray: list, log, console, console2, idScan, atomicInsert, ChClient, apiKey=None) -> list:
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

    printed_banner = False
    with console2.status(
        "[white]Searching vulnerabilities ...[/white]", spinner="bouncingBar"
    ) as status:
        for keyword in keywords:
            status.start()
            status.update(
                "[white]Searching vulnerability database for[/white] "
                + f"[red]{keyword}[/red] [white]...[/white]"
            )
            ApiResponseCVE = SearchKeyword(keyword, log, apiKey)
            status.stop()
            if len(ApiResponseCVE) == 0:
                continue

            if not printed_banner:
                banner(f"Possible vulnerabilities for {target}", "red", console)
                printed_banner = True

            #need rework console.print(f"┌─ [yellow][ {keyword} ][/yellow]")

            CVEs = []
            for CVE in ApiResponseCVE:
                CVEs.append(CVE.CVEID)
                #need rework console.print(f"│\n├─────┤ [red]{CVE.CVEID}[/red]\n│")
                CVEalreadyInTable = ChClient.query("select cCVEId from tScanCVE where cCVEId = " + CVE.CVEID, query_formats = {'String': 'string'})
                if CVEalreadyInTable.row_count == 0:
                    dataInsert = [[\
                                    CVE.CVEID,\
                                    None,\
                                    CVE.description,\
                                    CVE.severity\
                                    ]]
                    ChClient.insert(\
                                    table="tScanCVE",\
                                    data = dataInsert,\
                                    column_names = "cCVEId, cCVEName, cCVEDescription, cCVESeverity",\
                                    column_type_names = ['String', 'String', 'String', 'String'],\
                                    column_oriented = True,\
                                    )
                
                #formatting data for CH about CVE
                atomicInsert['CVEID'] = {\
                                        'cIPv4': target,\
                                        'nIPFlag': 0,\
                                        'cPort': PortArray[0][1],\
                                        'cTransProto': "TCP",\
                                        'cBanner': PortArray[0][3],\
                                        'cService': PortArray[0][2],\
                                        'cVersion': PortArray[0][4],\
                                        'cCVESeverity': CVE.severity,\
                                        'cCVEName': None
                                        }
                

                wrapped_description = wrap(CVE.description, term_width - 50)
               # need rework console.print(f"│\t\t[cyan]Description: [/cyan]")
                for line in wrapped_description:
                    #need rework console.print(f"│\t\t\t{line}")
                    pass
                """need rework console.print(
                    f"│\t\t[cyan]Severity: [/cyan]{CVE.severity} - {CVE.severity_score}\n"
                    + f"│\t\t[cyan]Exploitability: [/cyan] {CVE.exploitability}\n"
                    + f"│\t\t[cyan]Details: [/cyan] {CVE.details_url}"
                )"""

            VulnObject = VulnerableSoftware(title=keyword, CVEs=CVEs)
            VulnsArray.append(VulnObject)
            countPort += 1
            #console.print("└" + "─" * (term_width - 1))

    return VulnsArray
