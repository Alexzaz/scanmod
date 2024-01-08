from dataclasses import dataclass
from time import sleep

from requests import get


cache = {}


@dataclass
class Vulnerability:
    title: str
    CVEID: str
    description: str
    severity: str
    port: str


    def __str__(self) -> str:
        return (
            f"Title : {self.title}\n"
            + f"CVE_ID : {self.CVEID}\n"
            + f"Description : {self.description}\n"
            + f"Severity : {self.severity}\n"
        )


def FindVars(vuln: dict) -> tuple:
    CVE_ID = vuln["cve"]["id"]
    description = vuln["cve"]["descriptions"][0]["value"]

    severity = "UNKNOWN"


    if "cvssMetricV31" in vuln["cve"]["metrics"].keys():
        for _ in vuln["cve"]["metrics"]["cvssMetricV31"]:
            if _["type"].lower() == "primary":
                severity = _["cvssData"]["baseSeverity"]

    elif "cvssMetricV30" in vuln["cve"]["metrics"].keys():
        for _ in vuln["cve"]["metrics"]["cvssMetricV30"]:
            if _["type"].lower() == "primary":
                severity = _["cvssData"]["baseSeverity"]

    elif "cvssMetricV2" in vuln["cve"]["metrics"].keys():
        for _ in vuln["cve"]["metrics"]["cvssMetricV2"]:
            if _["type"].lower() == "primary":
                if _["cvssData"]["baseScore"] >= 9.0:
                    severity = "CRITICAL"
                else:
                    severity = _["baseSeverity"]

    return CVE_ID, description, severity


def searchCVE(keyword: tuple, log, apiKey=None) -> list:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&"
    if apiKey:
        sleep_time = 1.7
        headers = {"apiKey": apiKey}
    else:
        sleep_time = 8
        headers = {}

    if keyword[0][0] in cache and cache[keyword[0][0]][0].port == int(keyword[1]):
        return cache[keyword[0][0]]
    elif keyword[0][0] in cache:
        for _ in cache[keyword[0][0]]:
            _.port = int(keyword[1])
        return cache[keyword[0][0]]
    
    title_ = ''
    data = ''
    for tries in range(3):
        try:
            for value in keyword[0]:
                sleep(sleep_time)
                paramaters = {"keywordSearch": value}
                request = get(url, headers=headers, params=paramaters)
                data = request.json()
                if data['totalResults'] != 0:
                    title_ = value
                    break

        except Exception as e:
            if request.status_code == 403:
                log.logger(
                    "error",
                    "Requests are being rate limited by NIST API,"
                    + " please get a NIST API key to prevent this.",
                )
                sleep(sleep_time)
        else:
            break

    Vulnerabilities = []
    if data['totalResults'] == 0:
        return []


    for vuln in data["vulnerabilities"]:
        title = title_
        (
            CVE_ID,
            description,
            severity
        ) = FindVars(vuln)
        VulnObject = Vulnerability(
            title=title,
            CVEID=CVE_ID,
            description=description,
            severity=severity,
            port=int(keyword[1])
        )
        Vulnerabilities.append(VulnObject)

    cache[title_] = Vulnerabilities
    return Vulnerabilities
