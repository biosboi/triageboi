"""
Triageboi is a reverse engineering tool designed to 
decrease initial triage time by collecting multiple
simple tasks into one easy to use tool. The project
began in 2020 as a small script to consolidate file
data from multiple sources into one text file ready
for copying to any reporting template. Triageboi is
designed to be modular so analysts can decide which
types of data from files is pertinent to them. More
features are in the works, Stay tuned.
"""

import argparse
import hashlib
import os
import pefile
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms

# \/\/INSERT VT API KEY FOR VIRUSTOTAL ACCESS\/\/
VT_API_KEY: str = ""
# /\/\INSERT VT API KEY FOR VIRUSTOTAL ACCESS/\/\

"""
Globals are listed at the end of the file to improve
readability because the dictionaries are quite large
"""


def main() -> None:
    """Initiate tool"""
    # Set up argparse
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="triageboi",
        description="TRIAGEBOI is written and directed by biosboi.",
        epilog="""[I] By default, triageboi will create a single log for
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
        default="triageboi_log.txt",
        help="Specify log file name",
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
        help="Perform a recursive search if using directory",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Increase output verbosity including (Increases processing time)",
    )
    args: argparse.Namespace = parser.parse_args()

    # List of processed files
    triaged_files: list[FileData] = []

    def generate_file_data(file: str) -> FileData:
        """Take individual file and generate information to be logged"""
        file_type: str
        file_data: FileData

        try:
            # Run against single file
            with open(file=file, mode="rb") as handle_file:
                # Generate file information
                file_type = get_file_type(handle=handle_file)
                if file_type == "PE File":
                    file_data = PEData(
                        handle=handle_file, path=file, file_type=file_type, args=args
                    )
                elif file_type == "ELF File":
                    file_data = ELFData(
                        handle=handle_file, path=file, file_type=file_type
                    )
                else:
                    # Default file handler
                    file_data = FileData(
                        handle=handle_file, path=file, file_type=file_type
                    )
        except FileNotFoundError:
            print("[!] File not found: " + file)
            return None
        except Exception as e:
            # General exception handler
            print(f"[!] Error while processing file '{file}': {e}")
            return None

        return file_data

    def parse_paths(path: str) -> list[FileData]:
        """Check path type and recurse if requested"""
        file_data_list: list[FileData] = list()

        if os.path.isfile(path):
            # Run against individual file
            file_data_list.append(generate_file_data(path))
        elif os.path.isdir(path):
            # Run against entire directory
            for file in os.listdir(path):
                file = path + "/" + file
                if "triageboi" in file:
                    # Skip previously generated log files
                    pass
                elif os.path.isdir(file):
                    # If file is directory
                    if args.recursive:
                        file_data_list.extend(parse_paths(file))
                    else:
                        pass
                else:
                    # Individual file
                    file_data_list.append(generate_file_data(file))

        return file_data_list

    for path in args.path:
        # Iterate through every path in args and parse for files/directories
        triaged_files.extend(parse_paths(path))

    # Generate logs based on options
    log_buffer: str = ""
    for file in triaged_files:
        # Check Virustotal
        if args.virustotal:
            file.vt_result = VirusTotal(file.file_hash['SHA256'])
            file.vt_result.check_hash()
        # Generate log data
        log_buffer += read_file_data(file=file, args=args)

    # Output log data
    if args.print:
        print(log_buffer)
    if args.log:
        generate_log(file_name=args.log, log_output=log_buffer)


def get_file_type(handle) -> str:
    """Grab file type based on magic number."""
    magic: bytes
    handle.seek(0)
    magic = handle.read(3)
    # TODO Handle variable sized signatures

    for key, value in file_types.items():
        if magic in key or key in magic:
            return value
    return "Unknown File Type"


class FileData:
    """Represents individual file"""

    def __init__(self, handle, path, file_type):
        """Init file information"""
        self.path: str = path
        self.file_name: str = os.path.basename(self.path)
        self.file_type: str = file_type
        self.handle = handle
        self.file_size: int = os.path.getsize(self.path)
        self.file_hash: dict[str, str] = self._hash_file()
        self.vt_result: VirusTotal = None

    def _hash_file(self) -> dict:
        """Produce MD5, SHA1, and SHA256 hashes. Return as dictionary."""
        _hash_dict: dict[str, str] = {}

        # MD5
        self.handle.seek(0)
        _md5 = hashlib.md5()
        _buf = self.handle.read()
        _md5.update(_buf)

        # SHA-1
        self.handle.seek(0)
        _sha1 = hashlib.sha1()
        _buf = self.handle.read()
        _sha1.update(_buf)

        # SHA-256
        self.handle.seek(0)
        _sha256 = hashlib.sha256()
        _buf = self.handle.read()
        _sha256.update(_buf)

        # Build dict
        _hash_dict['MD5'] = _md5.hexdigest().upper()
        _hash_dict['SHA1'] = _sha1.hexdigest().upper()
        _hash_dict['SHA256'] = _sha256.hexdigest().upper()

        return _hash_dict


class PEData(FileData):
    """ "Represents individual file of type PE"""

    def __init__(self, handle, path, file_type, args):
        FileData.__init__(self, handle, path, file_type)
        # PE File Information
        self.pe_mach_type: str = "UNKNOWN"
        self.pe_compile_time: str = "UNKNOWN"
        self.pe_is_dll: bool = False
        self.pe_is_driver: bool = False
        self.pe_characteristics: list = []
        self.pe_version_info: dict = {}
        self.pe_certs: list[dict] = []
        # Additional Hashes Information
        self.pe_imphash: str = "UNKNOWN"
        self.pe_rich_header_hash: str = "UNKNOWN"
        # Import/Export Information
        self.pe_imports: dict[str, tuple[str]] = {}
        self.pe_exports: dict[int, str] = {}
        # PE Section Information
        self.pe_packer: str = "None Detected"
        self.pe_sections: list = []
        self.pe_tls: dict = {}
        self.funky_sections: list = []

        # Pefile Parsing
        try:
            if args.verbose:
                self._pe: pefile.PE = pefile.PE(name=path, fast_load=False)
            else:
                self._pe: pefile.PE = pefile.PE(name=path, fast_load=True)
            self._pe_dict: dict = self._pe.dump_dict()
        except pefile.PEFormatError:
            print(f"[!] {self.file_name} is not a valid PE file.")
            return

        # Machine Type
        self.pe_mach_type = pe_mach_types.get(
            self._pe_dict['FILE_HEADER']['Machine']['Value']
        )

        # Additional Hashes
        self.pe_imphash = self._pe.get_imphash().upper()
        self.pe_rich_header_hash = self._pe.get_rich_header_hash().upper()

        # 32-bit or 64-bit
        if self._pe.PE_TYPE == 0x10B:
            self.file_type += " - 32-bit"
        elif self._pe.PE_TYPE == 0x20B:
            self.file_type += " - 64-bit"
        else:
            self.file_type = "UNKNOWN"

        # PE Type
        if self._pe.is_dll():
            self.file_type += " (DLL)"
            self.pe_is_dll = True
        if self._pe.is_driver():
            self.file_type += " (Driver)"
            self.pe_is_driver = True

        # Characteristics
        _characteristics_val: int = self._pe_dict['FILE_HEADER']['Characteristics'][
            "Value"
        ]
        self.pe_characteristics = [
            _characteristic
            for _bit_value, _characteristic in pe_characteristics.items()
            if _characteristics_val & _bit_value
        ]

        # Compile Time
        self.pe_compile_time = self._pe_dict['FILE_HEADER']['TimeDateStamp'][
            "Value"
        ].split('[')[1][:-1]

        # Imports
        # Check if imports exist before processing
        _imported_symbols: dict = self._pe_dict.get("Imported symbols", [])
        for _import in _imported_symbols:
            # Skip import descriptor
            _import = _import[1:]
            # Grab DLL name
            _api: str = _import[0]['DLL'].decode("utf-8")
            # Assign functions to DLL in dictionary as list
            self.pe_imports[_api] = [
                # Handles when there is no name, but an ordinal
                (
                    func.get("Name", func.get("Ordinal", None)).decode("utf-8")
                    if func.get("Name")
                    else None
                )
                for func in _import
            ]
        # Delayed Imports
        # Check if delayed imports exist before processing
        _delay_imported_symbols: dict = self._pe_dict.get("Delay Imported symbols", [])
        for _import in _delay_imported_symbols:
            # Skip import descriptor
            _import = _import[1:]
            # Grab DLL name
            _api: str = _import[0]['DLL'].decode("utf-8")
            # Assign functions to DLL in dictionary as list
            self.pe_imports[_api] = [
                # Handles when there is no name, but an ordinal
                (
                    func.get("Name", func.get("Ordinal", None)).decode("utf-8")
                    if func.get("Name")
                    else None
                )
                for func in _import
            ]

        # Export Data
        # Check if exports exist before processing
        _exported_symbols: dict = self._pe_dict.get("Exported symbols", [])
        for _export in _exported_symbols:
            # Skip Export Directory
            for _export in self._pe_dict['Exported symbols'][1:]:
                # Check if the name exists
                if _export['Name'] is not None:
                    self.pe_exports[_export['Ordinal']] = _export['Name'].decode(
                        "utf-8"
                    )
                else:
                    # If no name, use only ordinal
                    self.pe_exports[_export['Ordinal']] = "<Unnamed Export>"

        # Sections
        for _section in self._pe_dict['PE Sections']:
            # Often section names have null bytes and/or whitespace attached
            _name: str = _section['Name']['Value'].strip("\\x00").strip()
            self.pe_sections.append(_name)
            # Rudimentary Funky section check
            if _name not in pe_common_sections:
                self.funky_sections.append(_name)
                # Packer check against section names
                for sec_name, packer in pe_packer_sections.items():
                    if _name in sec_name:
                        self.pe_packer = packer
                        break

        # TLS Data
        _tls_data: dict = self._pe_dict.get("TLS", [])
        # TODO TLS Data handler

        # Cert Data
        for _entry in self._pe_dict['Directories']:
            if _entry['Structure'] == "IMAGE_DIRECTORY_ENTRY_SECURITY":
                _cert_info: dict = _entry
                _sigoff: int = _cert_info['VirtualAddress']['Value']
                _sigsize: int = _cert_info['Size']['Value']
                if _sigoff > 0:
                    # Entry exists
                    self.handle.seek(_sigoff)
                    _raw_sig: bytes = self.handle.read(_sigsize)[8:]
                    # Catch invalid cert blocks
                    try:
                        _signature: cms.ContentInfo = cms.ContentInfo.load(
                            encoded_data=_raw_sig
                        )
                        for _cert in _signature['content']['certificates']:
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
                break

        # Version Information
        _version_info: dict = self._pe_dict.get("Version Information", [])
        if _version_info:
            # Handles first entry only. Couldn't identify a case where there
            # were more than one entries, so this should suffice. Could be
            # safer and handle additional entries in the future.
            try:
                for _entry in _version_info[0][2]:
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

        # Grab Header
        self.handle.seek(0)
        _elf_header = self.handle.read(0x14)

        self.elf_abi: str = elf_abi_types.get(_elf_header[0x7])
        self.elf_obj_type: str = elf_obj_types.get(_elf_header[0x10])
        self.elf_mach_type: str = elf_mach_types.get(_elf_header[0x12])

        # 32-bit or 64-bit
        if _elf_header[0x4] == 0x1:
            self.file_type += " - 32-bit"
        elif _elf_header[0x4] == 0x2:
            self.file_type += " - 64-bit"


class VirusTotal:
    """VirusTotal Controller"""

    def __init__(self, file_hash: str):
        self.headers = {"accept": "application/json", "X-Apikey": VT_API_KEY}
        self.url: str = "https://www.virustotal.com/api/v3/"
        self.file_hash: str = file_hash
        self.entries: list[dict] = []

    def check_hash(self):
        """Send hash to VirusTotal for analysis"""
        _url = self.url + "search?query=" + self.file_hash
        _response = requests.get(_url, headers=self.headers, timeout=10)
        _result = _response.json()
        if _response.status_code == 200 and len(_result['data']) > 0:
            for entry in _result['data']:
                self.entries.append(entry)
        else:
            pass
            # No entries found


def read_file_data(file: FileData, args: argparse.Namespace) -> str:
    """Read file data and generate string to be output to console or log"""
    output: str = ""

    # Create header
    output += (
        f"\n\n{'-' * 65}"
        f"\nTRIAGEBOI Output For File: {file.file_name}"
        f"\nTRIAGEBOI is Written and Directed by biosboi"
        f"\n{'-' * 65}"
        f"\n"
    )

    # Grab standard file data
    output += (
        f"\nStandard Data:"
        f"\nFile Name: {file.file_name}"
        f"\nFile Size: {file.file_size} Bytes"
        f"\nFile Type: {file.file_type}"
        f"\nMD5: {file.file_hash['MD5']}"
        f"\nSHA1: {file.file_hash['SHA1']}"
        f"\nSHA256: {file.file_hash['SHA256']}"
        f"\n"
    )

    # Grab VT results
    if args.virustotal:
        if not VT_API_KEY:
            output += (
                "\nVirusTotal API key not found. Please input API key to triageboi.py."
            )
        for entry in file.vt_result.entries:
            attr = entry['attributes']
            classification: str = None
            try:
                classification = attr['popular_threat_classification'][
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

    # Conditional prints based on file type
    if "PE" in file.file_type:
        # Standard PE Data
        output += (
            f"\n\nPE Data:"
            f"\nMachine Type: {file.pe_mach_type}"
            f"\nCompiled Time: {file.pe_compile_time}"
            f"\nPacker: {file.pe_packer}"
        )

        if args.verbose:
            # Import hash and Rich header hash
            output += (
                f"\nImphash: {file.pe_imphash}"
                f"\nRich Header Hash: {file.pe_rich_header_hash}"
            )

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
                        f"{cert.not_valid_before_utc.strftime("%m/%d/%y  %H:%M:%S")}"
                        f"\nInvalid After: "
                        f"{cert.not_valid_after_utc.strftime("%m/%d/%y  %H:%M:%S")}"
                        f"\nHash Algorithm: {cert.signature_hash_algorithm.name}"
                        f"\n--CERT END--"
                    )

        # Funky Section Names
        if file.funky_sections:
            output += "\n\nUnusual Section Names Found:\n"
            output += "\n".join(file.funky_sections)

    elif "ELF" in file.file_type:
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


def generate_log(file_name: str, log_output: str) -> None:
    """Create a log file for selected files"""
    try:
        # Generate log for single file
        with open(file=file_name, mode="wb") as handle_file:
            handle_file.write(log_output.encode("utf-8"))
    except IOError:
        print(f"[!] Unable to create log file for: {file_name}.")
    except TypeError:
        print(f"[!] Unable to create log file for: {file_name} due to type error.")


# Globals
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
pe_common_sections: dict = {
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
pe_packer_sections: dict = {
    # Sourced from: https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    "1\\x00ata": "Molebox",
    "1\\x00data": "Molebox",
    "1\\x00TA": "Molebox",
    "ext": "Molebox",
    ".alien": "Alienyze",
    ".aspack": "Aspack",
    ".adata": "Aspack/Armadillo",
    "ASPack": "Aspack",
    ".ASPack": "Aspack",
    ".boom": "The Boomerang List Builder (config+exe xored with a single byte key 0x77)",
    ".boot": "Themida",
    ".ccg": "CCG (Chinese)",
    ".charmve": "Added by the PIN tool",
    "BitArts": "Crunch 2.0",
    "DAStub": "DAStub Dragon Armor protector",
    "!EPack": "Epack",
    ".ecode": "Built with EPL",
    ".edata": "Built with EPL",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".ex_cod": "Expressor",
    ".packer": "Eronana",
    "FSG!": "FSG (not a section name, but a good identifier)",
    ".imrsiv": "special section used for applications that can be loaded to OS desktop bands.",
    ".gentee": "Gentee installer",
    ".jdpack": "JDPack",
    "kkrunchy": "kkrunchy",
    "lz32.dll": "Crinkler",
    ".mackt": "ImpRec-created section",
    ".MaskPE": "MaskPE",
    "MEW": "MEW",
    "MEW\\x00F\\x12\\xd2\\xc3": "Mew",
    "MEW\x00F\x12\xd2\xc3": "Mew",
    "2\\xd2u\\xdb\\x8a\\x16\\xeb\\xd4": "Mew",
    ".mnbvcx1": "most likely associated with Firseria PUP downloaders",
    ".mnbvcx2": "most likely associated with Firseria PUP downloaders",
    ".MPRESS1": "Mpress",
    ".MPRESS2": "Mpress",
    ".neolite": "Neolite",
    ".neolit": "Neolite",
    ".nsp1": "NsPack",
    ".nsp0": "NsPack",
    ".nsp2": "NsPack",
    "nsp1": "NsPack",
    "nsp0": "NsPack",
    "nsp2": "NsPack",
    "packerBY": "Bero",
    "bero^fr": "BeroPacker",
    ".PACKMAN": "Packman",
    "PEPACK!!": "Pepack",
    "pebundle": "PEBundle",
    "PEBundle": "PEBundle",
    "PEC2TO": "PECompact",
    "PEC2": "PECompact",
    "pec": "PECompact",
    "pec1": "PECompact",
    "pec2": "PECompact",
    "pec3": "PECompact",
    "pec4": "PECompact",
    "pec5": "PECompact",
    "pec6": "PECompact",
    "PEC2MO": "PECompact",
    "PELOCKnt": "PELock Protector",
    ".perplex": "Perplex PE-Protector",
    "PESHiELD": "PEShield",
    ".petite": "Petite",
    ".pinclie": "Added by the PIN tool",
    "ProCrypt": "ProCrypt",
    ".profile": "NightHawk C2 framework (by MDSec)",
    ".RLPack": "RLPack (second section)",
    ".rmnet": "Ramnit virus marker",
    "RCryptor": "RPCrypt",
    ".RPCrypt": "RPCrypt",
    ".seau": "SeauSFX",
    ".sforce3": "StarForce Protection",
    ".shrink1": "Shrinker",
    ".shrink2": "Shrinker",
    ".shrink3": "Shrinker",
    ".spack": "Simple Pack (by bagie)",
    ".svkp": "SVKP",
    "ta": "FSG",
    "Themida": "Themida",
    ".Themida": "Themida",
    ".themida": "Themida",
    ".taz": "Some version os PESpin",
    ".tsuarch": "TSULoader",
    ".tsustub": "TSULoader",
    ".packed": "Unknown",
    ".Upack": "Upack",
    ".ByDwing": "Upack",
    "PS\\xff\\xd5\\xab\\xeb\\xe7\\xc3": "Upack OR WinUPack",
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    "UPX3": "UPX",
    "UPX!": "UPX",
    ".UPX0": "UPX",
    ".UPX1": "UPX",
    ".UPX2": "UPX",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    "VProtect": "Vprotect",
    ".winapi": "Added by API Override tool",
    "WinLicen": "WinLicense (Themida) Protector",
    "_winzip_": "WinZip Self-Extractor",
    ".WWPACK": "WWPACK",
    ".WWP32": "WWPACK (WWPack32)",
    "yC": "Yoda Crypter",
    ".yP": "Y0da Protector",
    ".y0da": "Y0da Protector",
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

if __name__ == "__main__":
    main()
