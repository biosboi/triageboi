# TRIAGEBOI

Just another Python triage tool.
The main goal is to collect all required metadata into
one easily copyable log format for one or many files.

## Description

Triageboi is a reverse engineering tool designed to
decrease initial triage time by collecting multiple
simple tasks into one easy to use tool. The project
began in 2020 as a small script to consolidate file
data from multiple sources into one text file ready
for copying to any reporting template. Triageboi is
designed to be modular so analysts can decide which
types of data from files is pertinent to them.

The tool can be used against a single file or a whole directory
and allows recursive scanning as well. Each file will be scanned
and all information extracted will be logged to either the console,
a text file, or a json file.

All files recieve a "Basic Information" block including name, size,
hashes (MD5/SHA256), type, and any VirusTotal results if the VirusTotal
flag is set.

Additinally, PE files and ELF files will receive an additional information
block containing format specific details. Using the "-v" flag will increase
verbosity, generating even more information such as extracting certificates
from PE files.

## Getting Started

### Dependencies

* Python 3
* See requirements.txt for required modules

### Executing program

Python dependencies can be resolved with the command:
```
pip install -r requirements.txt
```

Executing triageboi.py on its own will create a log
in the same directory named triageboi_log.txt.

Use the command:
```
python triageboi.py -h
```
For additional options such as:
* Running recursively against a directory
* Printing log directly to console
* Increase verbosity on output
* Send hash to VirusTotal for results scanning
* Specify custom log name

## Version History
* 2.2.0 Progress bar Update
   * Added progress bar to scan
   * Additional readme notes on functionality
   * Bugfix when no log method is selected
* 2.1.0 JSON Output Update
   * Added basic JSON output logger
   * New ELF parser
   * SHA-1 Hashing is now commented out, MD5 and SHA256 remain
   * Some readability changes
* 2.0.0
   * Reworked file type detection using pyfsig
   * Added ELF parsing with pyelftools
   * Many bugfixes
   * Cleaner code throughout
* 1.2.1
    * Additional error handling and outlier detection
    * Formatting updates
* 1.2.0
    * PE File Version Information is now parsed
    * PE File Certificate Information is now parsed
    * Additional cleanups for readability
    * Additional error handling for outlier data
    * Unusual Section Names now output to log
    * Running non-verbose will now significantly reduce processing time
* 1.1.1
    * Recursive directory search bugfixes
    * Additional Packer Identifications
* 1.1.0
    * Allow offline use with attached Python wheels
* 1.0.0
    * Major rework
    * Added argparsing
    * Better error handling
    * Additional VirusTotal parsing
    * Many many bugfixes
* 0.1.0
    * Initial Release
