import argparse
import json
import os

import sys
import time
import requests

MAX_FAIL = 5
PAGESIZE = 2000
VERSION = 0.1
# Interval in seconds between successive requests
WAIT_PERIOD = 5

class OutputManager:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def print(self, string):
        if self.verbose:
            print(string)

def store_data(filename, data, count):
    with open(filename, "w") as file_handle:
        cvedata = {
            "CVE_data_type": "CVE",
            "CVE_data_format": "MITRE",
            "CVE_data_version": "4.0",
            "CVE_data_numberOfCVEs": count,
            "CVE_Items": data,
        }
        json.dump(cvedata, file_handle)

def process_data(elements):
    for cve_item in elements:
        # print(cve_item)
        cve = {
            "ID": cve_item["cve"]["CVE_data_meta"]["ID"],
            "description": cve_item["cve"]["description"]["description_data"][0][
                "value"
            ],
            "severity": "unknown",
            "score": "unknown",
            "CVSS_version": "unknown",
            "vector": "TBD",
            "problem": "unknown",
        }
        if "baseMetricV3" in cve_item["impact"]:
            cve["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                "baseSeverity"
            ]
            cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            cve["vector"] = cve_item["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
            cve["CVSS_version"] = 3
        elif "baseMetricV2" in cve_item["impact"]:
            cve["severity"] = cve_item["impact"]["baseMetricV2"]["severity"]
            cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            cve["vector"] = cve_item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
            cve["CVSS_version"] = 2
        if cve["vector"] != "TBD":
            try:
                # cve["problem"] = cve_item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
                check = cve_item["cve"]["problemtype"]["problemtype_data"][0][
                    "description"
                ]
                if len(check) > 0:
                    problem = ""
                    for data_item in cve_item["cve"]["problemtype"]["problemtype_data"][0][
                        "description"
                    ]:
                        # print (d["value"])
                        problem = data_item["value"] + ";"
                    cve["problem"] = problem[:-1]
            except:
                # print("Error with",cve_item["cve"]["CVE_data_meta"]["ID"] )
                pass
        print(cve["ID"], cve["score"], cve["severity"], cve["vector"], cve["problem"])

def get_data(startdate, enddate, outdir, config):
    nvd_feed = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    default_filename = "NVD_Data_1.json"
    index = 0
    # Extract configuration parameters
    verbose = config[0]
    pagesize = config[1]
    interval = config[2]
    show_data = config[3]
    # pagesize = 2000
    items = 0
    finished = False
    query_count = 0
    fail_count = 0
    file_data = []
    om = OutputManager(verbose)
    om.print(f"Retrieve CVEs from {startdate}")
    if enddate != "":
        om.print(f"Retrieve CVEs to {enddate}")
    while not finished:
        if enddate != "":
            query = {
                "resultsPerPage": pagesize,
                "startIndex": index,
                "pubStartDate": startdate,
                "pubEndDate": enddate,
            }
            filename = f"{outdir}NVD_data_{startdate[:4]}.json"
        else:
            query = {
                "resultsPerPage": pagesize,
                "startIndex": index,
                "modStartDate": startdate,
            }
            filename = f"{outdir}{default_filename}"
        try:
            response = requests.get(nvd_feed, params=query)
            om.print(f"Response :{response.status_code}")
            query_count += 1
            if response.status_code == 200:
                j = response.json()
                total_results = j["totalResults"]
                om.print(f"Query {query_count}")
                om.print(f"\tTotal results {total_results}")
                om.print(f"\tStart index {j['startIndex']}")
                no_of_results = j["resultsPerPage"]
                om.print(f"\tNumber of results returned: {no_of_results}")
                # Now process data
                if show_data:
                    process_data(j['result']["CVE_Items"])
                # filename = f"{outdir}NVD_data_{query_count}.json"
                # store_data(filename, j['result']["CVE_Items"], no_of_results)
                items = items + no_of_results
                for item in j["result"]["CVE_Items"]:
                    file_data.append(item.copy())
                # Have we finished?
                if items < total_results:
                    index = index + pagesize
                    # Calculate number of requests remaining
                    count = int((total_results - items) / pagesize) + 1
                    om.print(f"Estimated remaining time {count * interval} seconds")
                    # And wait
                    # om.print(f"Pause for {interval} seconds")
                    time.sleep(interval)
                else:
                    finished = True
                    store_data(filename, file_data, total_results)
                    om.print(f"Data saved in {filename}")
            else:
                fail_count += 1
                finished = fail_count == MAX_FAIL
                if not finished:
                    om.print(f"Pause for {interval} seconds")
                    time.sleep(interval)
        except:
            print(f"Failed to connect to NVD webservice {nvd_feed}")
            fail_count += 1
            finished = fail_count == MAX_FAIL
            if not finished:
                om.print(f"Pause for {interval} seconds")
                time.sleep(interval)
    return items


# Main
if __name__ == "__main__":

    desc = "Download NVD data and store data in JSON file"

    # Set all parser arguments here.
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, description=desc
    )

    parser.add_argument(
        "-o", "--output", help="Output directory", dest="output_directory", default="./"
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Name of file with time of last update",
        dest="update_file",
        default="",
    )
    parser.add_argument(
        "-d",
        "--date",
        help="Download all items modified from specified date (YYYY-MM-DD)",
        dest="start_date",
        default="",
    )
    parser.add_argument(
        "-a", "--all", help="Download all items", dest="all_items", action="store_true"
    )
    parser.add_argument(
        "-y",
        "--year",
        help="Download all items published for specified year (YYYY)",
        dest="year",
        default="",
    )
    parser.add_argument(
        "-t",
        "--time",
        help="Time (secs) between successive requests. Default "
        + str(WAIT_PERIOD)
        + " secs.",
        dest="interval",
        default=WAIT_PERIOD,
    )
    parser.add_argument(
        "-p",
        "--pagesize",
        help="Maximum number of items per request. Default "
        + str(PAGESIZE)
        + " items.",
        dest="page_size",
        default=PAGESIZE,
    )
    parser.add_argument(
        "-V", "--verbose", help="Verbose reporting", dest="verbose", action="store_true"
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Show version information and exit",
        dest="version",
        action="store_true",
    )
    parser.add_argument(
        "-s", "--show", help="Output retrieved records to console", dest="show_data", action="store_true"
    )

    # Parse arguments in case they are provided.
    params = parser.parse_args()
    version = params.version
    update_file = params.update_file
    all_items = params.all_items
    year = params.year
    # start_date = params.start_date
    output_directory = params.output_directory
    request_interval = int(params.interval)
    page_size = int(params.page_size)
    end_date = ""

    # Validate parameters
    if version:
        print("Version", VERSION)
        sys.exit(0)

    if page_size not in range(20, 5000):
        print(f"[ERROR] Specified request size ({page_size}) is out of range")
        sys.exit(-1)

    # Determine dates for record retrieval
    if update_file != "":
        # Time from last time file was updated
        try:
            update_time = os.path.getmtime(update_file)
            start_date = time.strftime(
                "%Y-%m-%dT%H:%M:%S:000 UTC-00:00", time.gmtime(update_time)
            )
        except OSError:
            print("[ERROR] File '%s' does not exist or is inaccessible" % update_file)
            sys.exit(-1)
    elif all_items:
        # All files since start of 1999
        start_date = "1999-01-01T00:00:00:000 UTC-00:00"
    elif year != "":
        start_date = f"{year}-01-01T00:00:00:000 UTC-00:00"
        end_date = f"{year}-12-31T23:59:59:000 UTC-00:00"
    elif params.start_date != "":
        start_date = f"{params.start_date}T00:00:00:000 UTC-00:00"
        # print ("Date",start_date)
    else:
        print("[ERROR] Start date not specified")
        sys.exit(-1)

    print(
        "Number of records retrieved",
        get_data(start_date, end_date, output_directory, [params.verbose, page_size, request_interval, params.show_data]),
    )

# End
