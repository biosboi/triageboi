# TRIAGEBOI

## Description

Triageboi is a reverse engineering tool designed to decrease initial triage time by scanning one or many files and generating metadata into several log formats (text or json). Special metadata blocks are generated for ELf, PE, and Mach-O files.

All files recieve a "Standard Information" block including name, size, hashes (MD5/SHA256), type, and any VirusTotal results if a VirusTotal API key is provided.

PE, ELF, and Mach-O binaries will receive an information block containing format specific details. Using the "-v" flag will increase verbosity, generating even more information such as displaying imports and extracting certificates from PE files.

### Motivation

The project began in 2020 as a small script to consolidate file data from multiple sources into one text file ready for copying to any reporting template. Single files are quick and easy to pull metadata from, but when receiving a dozen at a time for analysis, the process becomes increasingly prone to error. Triageboi seeks to resolve that issue by creating a single log file containing all scanned files' metadata for use in a reporting document or analysis notes.

## Getting Started

### Dependencies

* Python 3
* See requirements.txt for required modules

Python dependencies can be resolved with the command:
```
pip install -r requirements.txt
```
### Execution and Usage

Triageboi can execute against single files or directories. If running against a single file, add that file as an argument:
```
python triageboi.py <filename>
```

To run against an entire directory, either execute the script with no arguments to scan the current directory or provide the directory name
```
python triageboi.py
python triageboi.py <dirname>
```

Triageboi must be given a log format:
    -l, --log   : text log
    -j, --json  : json
    -p, --print : print to console
If no log flag is provided, triageboi will default to a (-l) text log.

If producing a log file, (as opposed to printing to the console) upon completion of the triageboi scan, a file will be created in the current working directory named triageboi_log_<timestamp>.<json|txt>.


A help menu can be displayed by using the -h,--help flag:
```
python triageboi.py -h
```
This menu provides information on additional options such as:
* Running recursively against a directory
* Increasing verbosity
* Sending hashes to VirusTotal (NOTE: Files are never uploaded to VirusTotal via this method, only hashes)
* Specify custom log name

## Version History
* 2.4.0 PE Parse Update
   * New PE Directory parsing
   * Better Version Information extraction
   * Safer PE log generation
   * Updated PE common section names
* 2.3.0 Mach-O Update
   * Added Mach-O parsing
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
