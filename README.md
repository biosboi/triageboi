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
types of data from files is pertinent to them. More
features are in the works, Stay tuned.


## Getting Started

### Dependencies

* Python 3
* See requirements.txt for required modules

### Executing program

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

* 1.0
    * Major rework
    * Added argparsing
    * Better error handling
    * Additional VirusTotal parsing
    * Many many bugfixes
* 0.1
    * Initial Release