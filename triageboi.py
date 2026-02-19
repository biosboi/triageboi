"""
Triageboi is a reverse engineering tool designed to
decrease initial triage time by collecting multiple
simple tasks into one easy to use tool. The project
began in 2020 as a small script to consolidate file
data from multiple sources into one text file ready
for copying to any reporting template. Triageboi is
designed to be modular so analysts can decide which
types of data from files is pertinent to them.
"""

# \/\/INSERT VT API KEY FOR VIRUSTOTAL ACCESS\/\/
VT_API_KEY: str = ""
# /\/\INSERT VT API KEY FOR VIRUSTOTAL ACCESS/\/\


# --- BEGIN IMPORTS ---

import time
import argparse
import hashlib
import json
import os
import requests
import pefile
import pyfsig as sig
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

# --- END IMPORTS ---


# --- BEGIN CLASSES ---


class FileData:
    """Represents individual file"""

    def __init__(self, handle, path: str, file_type: tuple[str, str] | None):
        """Standard file information"""
        self.bitness: str = "Unknown"
        self.path: str = path
        self.name: str = os.path.basename(self.path)
        self.handle = handle
        self.size: int = os.path.getsize(self.path)
        self.hash: dict[str, str] = self._hash_file()
        self.vt_result: VirusTotalData | None = None
        self.type: str = "Unknown"
        self.type_description: str = "Unknown"
        if file_type:
            # file_type is provided as (type,description) tuple
            self.type = file_type[0]
            self.type_description = file_type[1]

    def _hash_file(self) -> dict[str, str]:
        """Produce MD5, and SHA256 hashes. Return as dictionary."""
        _hash_dict: dict[str, str] = {}

        # MD5
        self.handle.seek(0)
        _md5 = hashlib.md5()
        _buf = self.handle.read()
        _md5.update(_buf)
        _hash_dict["MD5"] = _md5.hexdigest().upper()

        # SHA-1
        # self.handle.seek(0)
        # _sha1 = hashlib.sha1()
        # _buf = self.handle.read()
        # _sha1.update(_buf)
        # _hash_dict['SHA1'] = _sha1.hexdigest().upper()

        # SHA-256
        self.handle.seek(0)
        _sha256 = hashlib.sha256()
        _buf = self.handle.read()
        _sha256.update(_buf)
        _hash_dict["SHA256"] = _sha256.hexdigest().upper()

        return _hash_dict


class PEData(FileData):
    """Represents individual file of type PE"""

    def __init__(self, handle, path: str, file_type: tuple[str, str], verbose: bool):
        FileData.__init__(self, handle, path, file_type)
        # PE File Information
        self.pe_mach_type: str = "Unknown"
        self.pe_compile_time: str = "Unknown"
        self.pe_is_dll: bool = False
        self.pe_is_driver: bool = False
        self.pe_characteristics: list = []
        self.pe_version_info: dict = {}
        self.pe_certs: list[dict] = []
        # Additional Hashes Information
        self.pe_imphash: str = "Unknown"
        self.pe_rich_header_hash: str = "Unknown"
        # Import/Export Information
        self.pe_imports: dict[str, set[str]] = {}
        self.pe_exports: dict[int, str] = {}
        # PE Section Information
        self.pe_packers: set[str] = set()
        self.pe_sections: list[str] = []
        self.pe_tls: dict = {}
        self.funky_sections: list[str] = []

        self._pe: pefile.PE | None = None
        self._pe_dict: dict | None = None

        # ---------------------------- #
        # Pefile Parsing
        # ---------------------------- #
        try:
            if verbose:
                self._pe = pefile.PE(name=path, fast_load=False)
            else:
                self._pe = pefile.PE(name=path, fast_load=True)

            self._pe_dict = self._pe.dump_dict()
        except pefile.PEFormatError:
            print(f"[EE] {self.name} is not a valid PE file.")
            return

        # ---------------------------- #
        # Machine Type
        # ---------------------------- #
        self.pe_mach_type = pe_mach_types.get(
            self._pe_dict["FILE_HEADER"]["Machine"]["Value"]
        )

        # ---------------------------- #
        # Additional Hashes
        # ---------------------------- #
        self.pe_imphash = self._pe.get_imphash().upper()
        self.pe_rich_header_hash = str(self._pe.get_rich_header_hash()).upper()

        # ---------------------------- #
        # Bitness
        # ---------------------------- #
        if self._pe.PE_TYPE == 0x10B:
            self.bitness = "32"
        elif self._pe.PE_TYPE == 0x20B:
            self.bitness = "64"
        else:
            self.bitness = "Unknown"

        # ---------------------------- #
        # Library or Driver
        # ---------------------------- #
        if self._pe.is_dll():
            self.pe_is_dll = True
        if self._pe.is_driver():
            self.pe_is_driver = True

        # ---------------------------- #
        # Characteristics
        # ---------------------------- #
        _characteristics_val: int = self._pe_dict["FILE_HEADER"]["Characteristics"][
            "Value"
        ]
        self.pe_characteristics = [
            _characteristic
            for _bit_value, _characteristic in pe_characteristics.items()
            if _characteristics_val & _bit_value
        ]

        # ---------------------------- #
        # Compile Time
        # ---------------------------- #
        self.pe_compile_time = self._pe_dict["FILE_HEADER"]["TimeDateStamp"][
            "Value"
        ].split("[")[1][:-1]

        # ---------------------------- #
        # Imports
        # ---------------------------- #
        _api: str
        _imported_symbols: dict = self._pe_dict.get("Imported symbols", [])

        for _import in _imported_symbols:
            # Skip import descriptor
            _import = _import[1:]
            # Grab DLL name
            _dll_info = _import[0]["DLL"]
            _api = _dll_info.decode("utf-8") if _dll_info else "Unknown DLL"
            # Assign functions to DLL in dictionary as list
            self.pe_imports[_api] = {
                # Handles when there is an ordinal, but no name
                (
                    _func.get("Name", "").decode("utf-8")
                    if _func.get("Name")
                    else _func.get("Ordinal")
                )
                for _func in _import
            }

        # ---------------------------- #
        # Delayed Imports
        # ---------------------------- #
        _delay_imported_symbols: dict = self._pe_dict.get("Delay Imported symbols", [])

        for _import in _delay_imported_symbols:
            # Skip import descriptor
            _import = _import[1:]
            # Grab DLL name
            _dll_info = _import[0]["DLL"]
            _api = _dll_info.decode("utf-8") if _dll_info else "Unknown DLL"
            # Assign functions to DLL in dictionary as list
            self.pe_imports[_api] = {
                # Handles when there is no name, but an ordinal
                (
                    _func.get("Name", "").decode("utf-8")
                    if _func.get("Name")
                    else _func.get("Ordinal")
                )
                for _func in _import
            }

        # ---------------------------- #
        # Export Data
        # ---------------------------- #
        _exported_symbols: dict = self._pe_dict.get("Exported symbols", [])

        # Skip Export Directory
        for _export in _exported_symbols[1:]:
            # Check if the name exists
            if _export["Name"] is not None:
                self.pe_exports[_export["Ordinal"]] = _export["Name"].decode("utf-8")
            else:
                # If no name, use only ordinal
                self.pe_exports[_export["Ordinal"]] = "<Unnamed Export>"
        # Sort by ordinal
        self.pe_exports = dict(sorted(self.pe_exports.items()))

        # ---------------------------- #
        # Sections
        # ---------------------------- #
        for _section in self._pe_dict["PE Sections"]:
            # Sometimes section names have null bytes and/or whitespace attached
            _name: str = _section["Name"]["Value"].strip("\\x00").strip()
            self.pe_sections.append(_name)

            # Funky section check
            # Based on standard section name list, find outliers
            if _name not in pe_common_sections:
                self.funky_sections.append(_name)
                # Funky section names sometimes indicate a packer is present
                # Packer check against section names
                for packer, sec_names in pe_packer_sections.items():
                    if _name in sec_names:
                        self.pe_packers.add(packer)
                        break

        # ---------------------------- #
        # Directory Parser
        # ---------------------------- #
        for _entry in self._pe_dict["Directories"]:
            self.handle.seek(0)
            _sigoff: int = _entry["VirtualAddress"]["Value"]
            _sigsize: int = _entry["Size"]["Value"]
            _raw_sig: bytes

            ## TLS Data
            if _entry["Structure"] == "IMAGE_DIRECTORY_ENTRY_TLS":
                if _sigoff > 0:
                    # Entry exists
                    _raw_sig = self.handle.read(_sigsize)[8:]
                # TODO TLS Data handler

            ## Cert Data
            if _entry["Structure"] == "IMAGE_DIRECTORY_ENTRY_SECURITY":
                if _sigoff > 0:
                    # Entry exists
                    self.handle.seek(_sigoff)
                    _raw_sig = self.handle.read(_sigsize)[8:]
                    # Catch invalid cert blocks
                    try:
                        _signature: cms.ContentInfo = cms.ContentInfo.load(
                            encoded_data=_raw_sig
                        )
                        for _cert in _signature["content"]["certificates"]:
                            parsed_cert = x509.load_der_x509_certificate(
                                data=_cert.dump(),
                                backend=default_backend(),
                            )
                            self.pe_certs.append(parsed_cert)
                    except ValueError:
                        # Most failures appear to be associated with packers
                        pass
                    except TypeError:
                        # Most failures appear to be associated with packers
                        pass

        # ---------------------------- #
        # Version Information
        # ---------------------------- #
        _version_info: dict = self._pe_dict.get("Version Information", [])
        if _version_info:
            # Handles first entry only. Couldn't identify a case where there
            # were more than one entries, so this should suffice. Could be
            # safer and handle additional entries in the future.
            try:
                for _entry in _version_info:
                    if type(_entry):
                        # Potentially better way to handle entries
                        # TODO
                        ...
                    # Searches for valid entry
                    if isinstance(_entry, dict) and "Length" not in _entry:
                        self.pe_version_info = _entry
                        break
            except IndexError:
                # String info not found
                pass


class ELFData(FileData):
    """Represents individual file of type ELF"""

    def __init__(self, handle, path, file_type):
        FileData.__init__(self, handle, path, file_type)
        # ELF File Information
        self.handle.seek(0)
        _elf_header: bytes = self.handle.read(0x14)
        self.elf_abi: str = elf_abi_types.get(_elf_header[0x7])
        self.elf_obj_type: str = elf_obj_types.get(_elf_header[0x10])
        self.elf_mach_type: str = "Unknown"

        # ---------------------------- #
        # Generate ELFFile object
        # ---------------------------- #
        try:
            self._elf: ELFFile = ELFFile(handle)
        except ELFError as e:
            print(f"[EE] {self.name} is not a valid ELF file: {e}")
            return
        except Exception as e:
            print(f"[EE] {self.name} exception occured: {e}")
            return

        # ---------------------------- #
        # Machine Type
        # ---------------------------- #
        self.bitness = str(self._elf.elfclass)
        self.elf_mach_type = self._elf.get_machine_arch()

        # ---------------------------- #
        # Sections
        # ---------------------------- #
        _sections: list[dict] = []
        _sec: dict = {}

        for i in self._elf.iter_sections():
            _sec = dict(i.header)
            _sec["name"] = i.name if i.name else "None"
            _sections.append(_sec)

        # ---------------------------- #
        # Segments
        # ---------------------------- #
        _segments: list[dict] = []
        _seg: dict = {}

        for i in self._elf.iter_segments():
            _seg = dict(i.header)
            _segments.append(_seg)


class VirusTotalData:
    """VirusTotal Processing"""

    def __init__(self, file_hash: str):
        self.headers = {"accept": "application/json", "X-Apikey": VT_API_KEY}
        self.url: str = "https://www.virustotal.com/api/v3/"
        self.hash: str = file_hash
        self.entries: list[dict] = []

    def check_hash(self):
        """Send hash to VirusTotal for analysis"""
        _url: str = self.url + "search?query=" + self.hash
        _response = requests.get(_url, headers=self.headers, timeout=10)
        _result = _response.json()
        if _response.status_code == 200 and len(_result["data"]) > 0:
            for entry in _result["data"]:
                self.entries.append(entry)
        else:
            pass
            # No entries found


# --- END CLASSES ---

# --- BEGIN FUNCTIONS ---


def generate_file_data(file: str, options) -> FileData | None:
    """Take individual file and generate information to be logged"""
    poss_types: list[tuple[str, str]] = []
    file_type: tuple = ()

    try:
        with open(file=file, mode="rb") as opened_file:
            # Generate file information
            poss_types = get_file_type(handle=opened_file)

            if len(poss_types) != 1:
                # Default file handler multiple file types are identified
                return FileData(handle=opened_file, path=file, file_type=None)
            else:
                # Only one type identified, set as primary
                file_type = poss_types[0]

            # Match display string
            match file_type[0]:
                case "MZ":
                    return PEData(
                        handle=opened_file,
                        path=file,
                        file_type=file_type,
                        verbose=options.verbose,
                    )
                case ".ELF":
                    return ELFData(handle=opened_file, path=file, file_type=file_type)
                case _:
                    # Default file handler
                    return FileData(handle=opened_file, path=file, file_type=file_type)
    except FileNotFoundError:
        print("[EE] File not found: " + file)
        return None
    except Exception as e:
        # General exception handler
        print(f"[EE] Error while processing file '{file}': {e}")
        return None


def parse_paths(path: str, recurse: bool) -> list[str]:
    """Check path type and recurse if requested"""
    working_triage_list: list[str] = list()

    if os.path.isfile(path):
        # Run against individual file
        working_triage_list.append(path)
    elif os.path.isdir(path):
        # Run against entire directory
        for file in os.listdir(path):
            full_path = path + "/" + file
            if "triageboi_log" in full_path:
                # Skip previously generated log files
                pass
            elif os.path.isdir(full_path):
                # If file is directory
                if recurse:
                    working_triage_list.extend(parse_paths(full_path, recurse=recurse))
                else:
                    pass
            else:
                # Individual file
                working_triage_list.append(full_path)

    return working_triage_list


def get_file_type(handle) -> list[tuple[str, str]]:
    """Grab file type based on magic number."""
    magic: bytes

    handle.seek(0)
    magic = handle.read(32)
    poss_types: list[tuple[str, str]] = []

    matches: list[sig.interface.FileSignature] = sig.find_matches_for_file_header(
        file_header=magic
    )

    # List match(es) as (extension, description) tuple.
    for match in matches:
        poss_types.append((match.display_string, match.description))

    return poss_types


def parse_data_as_json(file: FileData) -> dict:
    """Given a file, generate a JSON friendly dictionary ready for logging"""
    data: dict = {}

    data["name"]    = file.name
    data["size"]    = file.size
    data["type"]    = file.type_description
    data["hashes"]  = file.hash
    data["bitness"] = file.bitness

    match file.type:
        case "MZ":
            data["pe_is_dll"]       = file.pe_is_dll
            data["pe_is_driver"]    = file.pe_is_driver
            data["pe_mach_type"]    = file.pe_mach_type
            data["pe_compile_time"] = file.pe_compile_time
            data["pe_packers"]      = list(file.pe_packers)
            data["pe_imphash"]      = file.pe_imphash
            data["pe_imports"]      = {
                dll: list(funcs) for dll, funcs in file.pe_imports.items()
            }
            data["pe_exports"]      = file.pe_exports
            data["pe_sections"]     = file.pe_sections
        case ".ELF":
            data["elf_abi"]         = file.elf_abi
            data["elf_mach_type"]   = file.elf_mach_type
            data["elf_obj_type"]    = file.elf_obj_type
        case _:
            pass

    return data


def read_file_data(file: FileData, options: argparse.Namespace) -> str:
    """Read file data and generate string to be output to console or log"""
    output: str = ""

    # Create header
    output += (
        f"\n\n{'-' * 65}"
        f"\nTRIAGEBOI Output For File: {file.name}"
        f"\n{'-' * 65}"
        f"\n"
    )

    # Grab standard file data
    output += (
        f"\nStandard Data:"
        f"\nFile Name: {file.name}"
        f"\nFile Size: {file.size} Bytes"
        f"\nFile Type: {file.type_description}"
        f"\nMD5: {file.hash['MD5']}"
        # f"\nSHA1: {file.hash['SHA1']}"
        f"\nSHA256: {file.hash['SHA256']}"
        f"\n"
    )

    # Grab VT results
    if file.vt_result:
        for entry in file.vt_result.entries:
            attr = entry["attributes"]
            classification: str | None = None
            try:
                classification = attr["popular_threat_classification"][
                    "suggested_threat_label"
                ]
            except KeyError:
                pass
            output += (
                "\nVirusTotal Data:"
                f"\nScore:"
                f"\n\tMalicious: {attr['last_analysis_stats']['malicious']}"
                f"\n\tSuspicious: {attr['last_analysis_stats']['suspicious']}"
                f"\n\tUndetected: {attr['last_analysis_stats']['undetected']}"
                f"\n\tHarmless: {attr['last_analysis_stats']['harmless']}"
                f"\nVotes (Harmless/Malicious): {attr['total_votes']['harmless']}/"
                f"{attr['total_votes']['malicious']}"
                f"\nTags: {[tag for tag in attr['tags']]}"
                f"\nOther Names: {[name for name in attr['names']]}"
            )
            if classification:
                output += f"\nSuggested Threat Label: {classification}"

    # Conditional information based on file type
    if "MZ" in file.type:
        # Standard PE Data
        output += (
            f"\n\nPE Data:"
            f"\nMachine Type: {file.pe_mach_type}"
            f"\nCompiled Time: {file.pe_compile_time}"
            f"\nPacker: {file.pe_packers if file.pe_packers else 'None detected'}"
        )

        if options.verbose:
            # Import hash and Rich header hash
            output += f"\nImphash: {file.pe_imphash}"
            if file.pe_rich_header_hash:
                output += f"\nRich Header Hash: {file.pe_rich_header_hash}"

            # Import Data
            output += "\n\nImports:"
            for imp in file.pe_imports.keys():
                output += f"\n{imp}"
            # Export Data
            if file.pe_exports:
                output += "\n\nExports:"
                for ordinal, export in file.pe_exports.items():
                    output += f"\n#{ordinal}: {export}"

            # Section Data
            output += "\n\nSections:\n"
            output += "\n".join(file.pe_sections)

            # Characteristics
            output += "\n\nCharacteristics:\n"
            output += "\n".join(file.pe_characteristics)

            # Version Information
            if file.pe_version_info:
                output += "\n\nVersion Information:"
                for key, value in file.pe_version_info.items():
                    # Check if the key/value is a byte string and decode it if so
                    key: str = key.decode("utf-8") if isinstance(key, bytes) else key
                    value: str = (
                        value.decode("utf-8") if isinstance(value, bytes) else value
                    )
                    output += f"\n{key}: {value}"

            # Certificate Information
            if file.pe_certs:
                output += "\n\nCertificate Information:"
                for cert in file.pe_certs:
                    output += (
                        f"\n--CERT BEGIN--"
                        f"\nIssuer: {cert.issuer.rfc4514_string()}"
                        f"\nSubject: {cert.subject.rfc4514_string()}"
                        f"\nVersion: {cert.version}"
                        f"\nInvalid Before: "
                        f"{cert.not_valid_before_utc.strftime('%m/%d/%y  %H:%M:%S')}"
                        f"\nInvalid After: "
                        f"{cert.not_valid_after_utc.strftime('%m/%d/%y  %H:%M:%S')}"
                        f"\nHash Algorithm: {cert.signature_hash_algorithm.name}"
                        f"\n--CERT END--"
                    )

        # Funky Section Names
        if file.funky_sections:
            output += "\n\nUnusual Section Names Found:\n"
            output += "\n".join(file.funky_sections)

    elif ".ELF" in file.type:
        # Standard ELF Data
        output += (
            f"\n\nELF Data:"
            f"\nABI: {file.elf_abi}"
            f"\nObject File Type: {file.elf_obj_type}"
            f"\nMachine Type: {file.elf_mach_type}\n"
        )
    else:
        pass
    return output


def generate_log(log_output: str) -> None:
    """Create a log file for selected files"""
    try:
        # Generate log for single file
        with open(file=TEXT_LOG_NAME, mode="wb+") as opened_file:
            opened_file.write(log_output.encode("utf-8"))
    except IOError as e:
        print(f"{e}")
    except TypeError as e:
        print(f"{e}")


def generate_json_log(files_to_process: list) -> None:
    """Create json file with log information"""

    json_parsed_files = [parse_data_as_json(file=file) for file in files_to_process]
    try:
        with open(file=JSON_LOG_NAME, mode="w+", encoding="utf-8") as log:
            json.dump(obj=json_parsed_files, fp=log, indent=4)
    except IOError as e:
        print(f"{e}")
    except TypeError as e:
        print(f"{e}")


def main(options: argparse.Namespace) -> None:
    """Initiate tool"""

    # List of files to triage
    files_to_triage: list[str] = []
    # List of processed files
    triaged_files: list[FileData | None] = []
    filtered_files: list[FileData] = []
    # Working log string
    log_buffer: str = ""

    # Generate list of files to analyze
    for path in options.path:
        # Iterate through every path in options and parse for files/directories
        files_to_triage.extend(parse_paths(path=path, recurse=options.recursive))

    # Process all identified files
    for file in files_to_triage:
        triaged_files.append(generate_file_data(file=file, options=options))
    filtered_files = [item for item in triaged_files if item is not None]

    # Generate logs based on options
    for file in filtered_files:
        if options.virustotal:
            # Check Virustotal
            file.vt_result = VirusTotalData(file.hash["SHA256"])
            file.vt_result.check_hash()
        # Generate log data
        log_buffer += read_file_data(file=file, options=options)

    # Outpout log data to JSON log file
    if options.json:
        generate_json_log(files_to_process=filtered_files)
    # Output log data to console
    if options.print:
        print(log_buffer)
    # Output log data to log file
    if options.log:
        generate_log(log_output=log_buffer)


# --- END FUNCTIONS ---

# --- BEGIN GLOBALS ---

CUR_TIME = time.strftime("%Y%m%d_%H%M%S")
TEXT_LOG_NAME = f"triageboi_log_{CUR_TIME}.txt"
JSON_LOG_NAME = f"triageboi_json_{CUR_TIME}.json"

VERSION = "2.1.0"

file_types: dict = {
    b"MZ": "PE File",
    b"MZ\x90": "PE File",
    b"\x7fELF": "ELF File",
    b"PK": "DOCX/XLSX/PPTX/Jar/Zip File",
    b"\x25PDF-": "PDF Document",
    b"\x1f\x8b": "GZip File",
    b"\x75\x73\x74\x61\x72": "Tar Archive",
    b"\xd0\xcf\x11\xe0\xa1": "Compound File Binary Format",
    b"\x1f\x9d": "Compressed File (Tar or Zip)",
    b"\x1f\xa0": "Compressed File (Tar or Zip)",
    b"\x52\x61\x72": "Rar Archive",
    b"\x37\x7a\xbc\xaf": "7-Zip File",
    b"\xff\xd8": "JPEG Image",
    b"\x89PN": "PNG Image",
    b"BM": "BMP Image",
    b"GIF": "GIF Image",
    b"\x6b\x6f\x6c\x79": "Apple Disk Image File",
    b"\xfe\xed\xfa\xce": "Mach-O Binary (32-bit)",
    b"\xfe\xed\xfa\xcf": "Mach-O Binary (64-bit)",
    b"#!": "Shebang Script",
}

pe_mach_types: dict = {
    0x0: "UNKNOWN",
    0x184: "Alpha AXP",
    0x284: "Alpha 64",
    0x1D3: "Matsushita AM33",
    0x8664: "x64",
    0x1C0: "ARM little endian",
    0xAA64: "ARM64 little endian",
    0x1C4: "ARM Thumb-2 little endian",
    0xEBC: "EFI byte code",
    0x14C: "Intel 386 or later processors and compatible processors",
    0x200: "Intel Itanium processor family",
    0x6232: "LoongArch 32-bit processor family",
    0x6264: "LoongArch 64-bit processor family",
    0x9041: "Mitsubishi M32R little endian",
    0x266: "MIPS16",
    0x366: "MIPS with FPU",
    0x466: "MIPS16 with FPU",
    0x1F0: "Power PC little endian",
    0x1F1: "Power PC with floating point support",
    0x166: "MIPS little endian",
    0x5032: "RISC-V 32-bit address space",
    0x5064: "RISC-V 64-bit address space",
    0x5128: "RISC-V 128-bit address space",
    0x1A2: "Hitachi SH3",
    0x1A3: "Hitachi SH3 DSP",
    0x1A6: "Hitachi SH4",
    0x1A8: "Hitachi SH5",
    0x1C2: "Thumb",
    0x169: "MIPS little-endian WCE v2",
}

pe_common_sections: set = {
    ".text",
    ".bss",
    ".rdata",
    ".data",
    ".pdata",
    ".reloc",
    ".edata",
    ".idata",
    ".tls",
    ".debug",
    ".rsrc",
    ".gfids",
}

pe_characteristics: dict = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0010: "AGGRESSIVE_WS_TRIM",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0040: "RESERVED",
    0x0080: "BYTES_REVERSED_LO",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x0400: "REMOVABLE_RUN_FROM_SWAP",
    0x0800: "NET_RUN_FROM_SWAP",
    0x1000: "SYSTEM",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
    0x8000: "BYTES_REVERSED_HI",
}

pe_packer_sections: dict[str, set[str]] = {
    # Sourced from: https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    "Molebox": {"1\\x00ata", "1\\x00data", "1\\x00TA", "ext"},
    "Alienyze": {".alien"},
    "Aspack": {".aspack", "ASPack", ".ASPack"},
    "Aspack/Armadillo": {".adata"},
    "The Boomerang List Builder (config+exe xored with a single byte key 0x77)": {
        ".boom"
    },
    "Themida": {".boot", "Themida", ".Themida", ".themida"},
    "CCG (Chinese)": {"ccg"},
    "Added by the PIN tool": {".charmve", ".pinclie"},
    "Crunch 2.0": {"BitArts"},
    "DAStub Dragon Armor protector": {"DAStub"},
    "Epack": {"!Epack"},
    "Built with EPL": {".ecode", ".edata"},
    "Enigma Protector": {".enigma1", ".enigma2"},
    "Expressor": {".ex_cod"},
    "Eronana": {".packer"},
    "FSG (not a section name, but a good identifier)": {"FSG!"},
    "special section used for applications that can be loaded to OS desktop bands.": {
        ".imrsiv"
    },
    "Gentee installer": {".gentee"},
    "JDPack": {".jdpack"},
    "kkrunchy": {"kkrunchy"},
    "Crinkler": {"lz32.dll"},
    "ImpRec-created section": {".mackt"},
    "MaskPE": {".MaskPE"},
    "Mew": {
        "MEW",
        "MEW\\x00F\\x12\\xd2\\xc3",
        "MEW\x00F\x12\xd2\xc3",
        "2\\xd2u\\xdb\\x8a\\x16\\xeb\\xd4",
    },
    "most likely associated with Firseria PUP downloaders": {".mnbvcx1", ".mnbvcx2"},
    "Mpress": {".MPRESS1", ".MPRESS2"},
    "Neolite": {".neolit", ".neolite"},
    "NsPack": {".nsp1", ".nsp0", ".nsp2", "nsp0", "nsp1", "nsp2"},
    "Bero": {"packerBY"},
    "BeroPacker": {"bero^fr"},
    "Packman": {".PACKMAN"},
    "Pepack": {"PEPACK!!"},
    "PEBundle": {"pebundle", "PEBundle"},
    "PECompact": {
        "PEC2TO",
        "PEC2",
        "pec",
        "pec1",
        "pec2",
        "pec3",
        "pec4",
        "pec5",
        "pec6",
        "PEC2MO",
    },
    "PELock Protector": {"PELOCKnt"},
    "Perplex PE-Protector": {".perplex"},
    "PEShield": {"PESHiELD"},
    "Petite": {".petite"},
    "ProCrypt": {"ProCrypt"},
    "NightHawk C2 framework (by MDSec)": {".profile"},
    "RLPack (second section)": {".RLPack"},
    "Ramnit virus marker": {".rmnet"},
    "RPCrypt": {"RCryptor", ".RPCrypt"},
    "SeauSFX": {".seau"},
    "StarForce Protection": {".sforce3"},
    "Shrinker": {".shrink1", ".shrink2", ".shrink3"},
    "Simple Pack (by bagie)": {".spack"},
    "SVKP": {".svkp"},
    "FSG": {"ta"},
    "Some version os PESpin": {".taz"},
    "TSULoader": {".tsuarch", ".tsustub"},
    "Unknown": {".packed"},
    "Upack": {".Upack", ".ByDwing"},
    "Upack OR WinUPack": {"PS\\xff\\xd5\\xab\\xeb\\xe7\\xc3"},
    "UPX": {"UPX0", "UPX1", "UPX2", "UPX3", "UPX!", ".UPX0", ".UPX1", ".UPX2"},
    "VMProtect": {".vmp0", ".vmp1", ".vmp2"},
    "Vprotect": {"VProtect"},
    "Added by API Override tool": {".winapi"},
    "WinLicense (Themida) Protector": {"WinLicen"},
    "WinZip Self-Extractor": {"_winzip_"},
    "WWPACK": {".WWPACK"},
    "WWPACK (WWPack32)": {".WWP32"},
    "Yoda Crypter": {"yC"},
    "Y0da Protector": {".yP", ".y0da"},
}

elf_abi_types: dict = {
    0x0: "System V",
    0x1: "HP-UX",
    0x2: "NetBSD",
    0x3: "Linux",
    0x4: "GNU Hurd",
    0x6: "Solaris",
    0x7: "AIX",
    0x8: "IRIX",
    0x9: "FreeBSD",
    0xA: "Tru64",
    0xB: "Novell Modesto",
    0xC: "OpenBSD",
    0xD: "OpenVMS",
    0xE: "NonStop Kernel",
    0xF: "AROS",
    0x10: "Fenix OS",
    0x11: "CloudABI",
    0x12: "Stratus Technologies OpenVOS",
}

elf_obj_types: dict = {
    0x0: "None",
    0x1: "Relocatable",
    0x2: "Executable",
    0x3: "Shared Object",
    0x4: "Core",
}

elf_mach_types: dict = {
    0x00: "No specific instruction set",
    0x01: "AT&T WE 32100",
    0x02: "SPARC",
    0x03: "x86",
    0x04: "Motorola 68000 (M68k)",
    0x05: "Motorola 88000 (M88k)",
    0x06: "Intel MCU",
    0x07: "Intel 80860",
    0x08: "MIPS",
    0x09: "IBM System/370",
    0x0A: "MIPS RS3000 Little-endian",
    0x0E: "Hewlett-Packard PA-RISC",
    0x0F: "Reserved for future use",
    0x13: "Intel 80960",
    0x14: "PowerPC",
    0x15: "PowerPC (64-bit)",
    0x16: "S390, including S390x",
    0x17: "IBM SPU/SPC",
    0x24: "NEC V800",
    0x25: "Fujitsu FR20",
    0x26: "TRW RH-32",
    0x27: "Motorola RCE",
    0x28: "ARM (up to ARMv7/Aarch32)",
    0x29: "Digital Alpha",
    0x2A: "SuperH",
    0x2B: "SPARC Version 9",
    0x2C: "Siemens TriCore embedded processor",
    0x2D: "Argonaut RISC Core",
    0x2E: "Hitachi H8/300",
    0x2F: "Hitachi H8/300H",
    0x30: "Hitachi H8S",
    0x31: "Hitachi H8/500",
    0x32: "IA-64",
    0x33: "Stanford MIPS-X",
    0x34: "Motorola ColdFire",
    0x35: "Motorola M68HC12",
    0x36: "Fujitsu MMA Multimedia Accelerator",
    0x37: "Siemens PCP",
    0x38: "Sony nCPU embedded RISC processor",
    0x39: "Denso NDR1 microprocessor",
    0x3A: "Motorola Star*Core processor",
    0x3B: "Toyota ME16 processor",
    0x3C: "STMicroelectronics ST100 processor",
    0x3D: "Advanced Logic Corp. TinyJ embedded processor family",
    0x3E: "AMD x86-64",
    0x8C: "TMS320C6000 Family",
    0xAF: "MCST Elbrus e2k",
    0xB7: "ARM 64-bits (ARMv8/Aarch64)",
    0xF3: "RISC-V",
    0xF7: "Berkeley Packet Filter",
    0x101: "WDC 65C816",
}


# --- END GLOBALS ---


# --- BEGIN SETUP ---


if __name__ == "__main__":

    # Set up argparse
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="triageboi.py",
        description=f"triageboi {VERSION} is written and directed by biosboi.",
        epilog="""[II] By default, triageboi will create a single log for
        every file in the directory it's located in.""",
    )
    parser.add_argument(
        "path",
        type=str,
        nargs="*",
        default=".",
        help="Path to file or directory",
    )
    parser.add_argument(
        "-a",
        "--virustotal",
        action="store_true",
        default=False,
        help="Perform VirusTotal hash check (Requires API key written in triageboi.py)",
    )
    parser.add_argument(
        "-l",
        "--log",
        action="store_true",
        default=False,
        help="Generate text log",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        default=False,
        help="Generate JSON log",
    )
    parser.add_argument(
        "-p",
        "--print",
        action="store_true",
        default=False,
        help="Print log data to console",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        default=False,
        help="Perform a recursive scan on a directory",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Increase output details (longer processing time)",
    )
    args: argparse.Namespace = parser.parse_args()

    main(options=args)


# --- END SETUP ---
