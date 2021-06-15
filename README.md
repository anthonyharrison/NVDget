# NVDget README

NVDGET downloads data from NVD CVE repository into a JSON file.

Usage:

`nvdget.py [-h] [-o OUTPUT_DIRECTORY] [-f UPDATE_FILE] [-d START_DATE]
                 [-a] [-y YEAR] [-t INTERVAL] [-p PAGE_SIZE] [-V] [-v] [-s]`


optional arguments:
```
  -h, --help            show this help message and exit
  -o OUTPUT_DIRECTORY, --output OUTPUT_DIRECTORY
                        Output directory
  -f UPDATE_FILE, --file UPDATE_FILE
                        Name of file with time of last update
  -d START_DATE, --date START_DATE
                        Download all items modified from specified date (YYYY-MM-DD)
  -a, --all             Download all items
  -y YEAR, --year YEAR  Download all items published for specified year (YYYY)
  -t INTERVAL, --time INTERVAL
                        Time (secs) between successive requests. Default 5 secs.
  -p PAGE_SIZE, --pagesize PAGE_SIZE
                        Maximum number of items per request. Default 2000 items.
  -V, --verbose         Verbose reporting
  -v, --version         Show version information and exit
  -s, --show            Output retrieved records to console
```
