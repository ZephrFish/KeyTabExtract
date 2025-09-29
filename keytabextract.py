#!/usr/bin/env python3
"""
KeyTabExtract: Extract hashes from Kerberos keytab files with timestamps.
Shows all keys sorted by timestamp (newest first) for each service principal.

Features:
- Multiple keytab version support (0501, 0502)
- Hash verification
- Colourised output
- Batch processing of multiple keytab files
- Multiple hash format options (plain, hashcat, john)
- Comprehensive logging
- Dry-run mode for analysis without extraction
"""

import argparse
import binascii
import datetime
import logging
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

# Try to import colorama for coloured output
try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
    HAS_COLOURS = True
except ImportError:
    HAS_COLOURS = False
    # Create dummy colour constants
    class DummyFore:
        def __getattr__(self, name: str) -> str:
            return ""
    class DummyStyle:
        def __getattr__(self, name: str) -> str:
            return ""
    Fore = DummyFore()
    Style = DummyStyle()

# Configure logger
logger = logging.getLogger("keytabextract")

# Constants
MAX_KEYTAB_SIZE: int = 100 * 1024 * 1024  # 100MB limit
HEADER_SIZE: int = 12  # Skip version and size fields
VERSION_FIELD_SIZE: int = 4
COMPONENT_COUNT_SIZE: int = 4
REALM_LENGTH_SIZE: int = 4
COMPONENT_LENGTH_SIZE: int = 4
TIMESTAMP_SIZE: int = 8
KVNO_SIZE: int = 2
KEYTYPE_SIZE: int = 4
KEYLEN_SIZE: int = 4
NAMETYPE_SIZE: int = 8

SUPPORTED_VERSIONS: List[str] = ["0501", "0502"]


class HashFormat(Enum):
    """Output format for hashes."""
    PLAIN = "plain"
    HASHCAT = "hashcat"
    JOHN = "john"


class EncryptionType(Enum):
    """Supported encryption types."""
    RC4_HMAC = "0017"
    AES256_CTS_HMAC_SHA1 = "0012"
    AES128_CTS_HMAC_SHA1 = "0011"


@dataclass
class EncryptionInfo:
    """Information about an encryption type."""
    name: str
    display: str
    hash_length: int
    pattern_suffix: str


# Encryption type definitions
ENCRYPTION_TYPES: Dict[str, EncryptionInfo] = {
    EncryptionType.RC4_HMAC.value: EncryptionInfo(
        name="RC4-HMAC",
        display="NTLM",
        hash_length=32,
        pattern_suffix="0010"
    ),
    EncryptionType.AES256_CTS_HMAC_SHA1.value: EncryptionInfo(
        name="AES256-CTS-HMAC-SHA1",
        display="AES-256",
        hash_length=64,
        pattern_suffix="0020"
    ),
    EncryptionType.AES128_CTS_HMAC_SHA1.value: EncryptionInfo(
        name="AES128-CTS-HMAC-SHA1",
        display="AES-128",
        hash_length=32,
        pattern_suffix="0010"
    )
}


@dataclass
class KeyEntry:
    """Represents a single key entry from a keytab."""
    timestamp: int
    timestamp_str: str
    kvno: int
    encryption_type: str
    hash_value: str

    def __lt__(self, other: 'KeyEntry') -> bool:
        """Sort by timestamp (newest first)."""
        return self.timestamp > other.timestamp


@dataclass
class ServicePrincipal:
    """Represents a service principal with its keys."""
    name: str
    realm: str
    keys: List[KeyEntry] = field(default_factory=list)

    def add_key(self, key: KeyEntry) -> None:
        """Add a key entry to this service principal."""
        self.keys.append(key)
        self.keys.sort()  # Keep sorted by timestamp


@dataclass
class KeytabData:
    """Container for all extracted keytab data."""
    version: str
    file_path: str
    principals: Dict[str, ServicePrincipal] = field(default_factory=dict)

    def add_entry(self, realm: str, principal_name: str, key: KeyEntry) -> None:
        """Add a key entry to the appropriate service principal."""
        full_name = f"{principal_name}@{realm}"
        if full_name not in self.principals:
            self.principals[full_name] = ServicePrincipal(
                name=principal_name,
                realm=realm
            )
        self.principals[full_name].add_key(key)


class KeyTabParser(ABC):
    """Abstract base class for version-specific keytab parsers."""

    @abstractmethod
    def extract_entry(self, hex_data: str, pointer: int) -> Tuple[Optional[Tuple[str, str, KeyEntry]], int]:
        """
        Extract a single entry from the keytab.

        Returns:
            Tuple containing (realm, principal, key_entry) and new pointer position
        """
        pass


class KeyTabParserV0501(KeyTabParser):
    """Parser for keytab version 0501."""

    def extract_entry(self, hex_data: str, pointer: int) -> Tuple[Optional[Tuple[str, str, KeyEntry]], int]:
        """Extract entry using v0501 format."""
        # For now, v0501 uses the same format as v0502
        # This would be implemented differently for actual v0501 format
        parser = KeyTabParserV0502()
        return parser.extract_entry(hex_data, pointer)


class KeyTabParserV0502(KeyTabParser):
    """Parser for keytab version 0502."""

    def extract_entry(self, hex_data: str, pointer: int) -> Tuple[Optional[Tuple[str, str, KeyEntry]], int]:
        """Extract entry using v0502 format."""
        try:
            # Number of components
            num_components = int(hex_data[pointer:pointer+COMPONENT_COUNT_SIZE], 16)
            pointer += COMPONENT_COUNT_SIZE

            # Realm length and value
            realm_len = int(hex_data[pointer:pointer+REALM_LENGTH_SIZE], 16)
            pointer += REALM_LENGTH_SIZE

            realm_end = pointer + (realm_len * 2)
            realm = bytes.fromhex(hex_data[pointer:realm_end]).decode('utf-8')
            pointer = realm_end

            # Extract components
            components = []
            for _ in range(num_components):
                comp_len = int(hex_data[pointer:pointer+COMPONENT_LENGTH_SIZE], 16)
                pointer += COMPONENT_LENGTH_SIZE
                comp_end = pointer + (comp_len * 2)
                component = bytes.fromhex(hex_data[pointer:comp_end]).decode('utf-8')
                components.append(component)
                pointer = comp_end

            service_principal = "/".join(components)

            # Skip name type
            pointer += NAMETYPE_SIZE

            # Timestamp
            timestamp = int(hex_data[pointer:pointer+TIMESTAMP_SIZE], 16)
            timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            pointer += TIMESTAMP_SIZE

            # Key version number
            kvno = int(hex_data[pointer:pointer+KVNO_SIZE], 16)
            pointer += KVNO_SIZE

            # Key type
            keytype_hex = hex_data[pointer:pointer+KEYTYPE_SIZE]
            pointer += KEYTYPE_SIZE

            # Key length and value
            key_len = int(hex_data[pointer:pointer+KEYLEN_SIZE], 16)
            pointer += KEYLEN_SIZE

            key_val_end = pointer + (key_len * 2)
            key_val = hex_data[pointer:key_val_end]
            pointer = key_val_end

            # Create key entry
            key = KeyEntry(
                timestamp=timestamp,
                timestamp_str=timestamp_str,
                kvno=kvno,
                encryption_type=keytype_hex,
                hash_value=key_val
            )

            # Skip padding and find next entry
            pointer = self._skip_padding(hex_data, pointer)

            return (realm, service_principal, key), pointer

        except Exception as e:
            logger.debug(f"Error parsing entry at position {pointer}: {str(e)}")
            return None, pointer + 8

    def _skip_padding(self, hex_data: str, pointer: int) -> int:
        """Skip padding bytes and alignment."""
        try:
            # Try to skip next size field
            if pointer + 8 <= len(hex_data):
                pointer += 8

            # Skip alignment bytes
            while pointer < len(hex_data) and hex_data[pointer:pointer+2] == "00":
                pointer += 2

            # Handle special marker
            if pointer < len(hex_data) and hex_data[pointer:pointer+4] == "ffff":
                pointer += 8

        except ValueError:
            # Skip any padding bytes
            while pointer < len(hex_data) and hex_data[pointer:pointer+2] == "00":
                pointer += 2

            if pointer < len(hex_data) and hex_data[pointer:pointer+4] == "ffff":
                pointer += 8

        return pointer


class HashFormatter:
    """Formats hashes according to specified output format."""

    @staticmethod
    def format(
        hash_format: HashFormat,
        enc_type: str,
        hash_value: str,
        realm: str,
        service_principal: str
    ) -> str:
        """Format a hash according to the specified output format."""
        if hash_format == HashFormat.PLAIN:
            return hash_value
        elif hash_format == HashFormat.HASHCAT:
            return HashFormatter._format_hashcat(enc_type, hash_value, realm, service_principal)
        elif hash_format == HashFormat.JOHN:
            return HashFormatter._format_john(enc_type, hash_value, realm, service_principal)
        return hash_value

    @staticmethod
    def _format_hashcat(enc_type: str, hash_value: str, realm: str, principal: str) -> str:
        """Format for hashcat."""
        if enc_type == EncryptionType.RC4_HMAC.value:
            return f"{hash_value}:{principal}"
        elif enc_type in (EncryptionType.AES256_CTS_HMAC_SHA1.value, EncryptionType.AES128_CTS_HMAC_SHA1.value):
            return f"{hash_value}:{principal}:{realm}"
        return hash_value

    @staticmethod
    def _format_john(enc_type: str, hash_value: str, realm: str, principal: str) -> str:
        """Format for John the Ripper."""
        if enc_type == EncryptionType.RC4_HMAC.value:
            return f"{principal}:{hash_value}"
        elif enc_type in (EncryptionType.AES256_CTS_HMAC_SHA1.value, EncryptionType.AES128_CTS_HMAC_SHA1.value):
            return f"{principal}@{realm}:{hash_value}"
        return f"{principal}:{hash_value}"


class KeyTabExtractor:
    """Extract and process hashes from Kerberos keytab files."""

    def __init__(
        self,
        keytab_path: str,
        verbose: bool = False,
        no_colour: bool = False,
        hash_format: HashFormat = HashFormat.PLAIN,
        dry_run: bool = False
    ):
        """
        Initialise the KeyTabExtractor.

        Args:
            keytab_path: Path to the keytab file
            verbose: Enable verbose output
            no_colour: Disable coloured output
            hash_format: Format for hash output
            dry_run: Analyse without extracting hashes
        """
        self.keytab_path: str = keytab_path
        self.hex_encoded: str = ""
        self.keytab_data: Optional[KeytabData] = None
        self.verbose: bool = verbose
        self.use_colour: bool = HAS_COLOURS and not no_colour
        self.hash_format: HashFormat = hash_format
        self.dry_run: bool = dry_run
        self.parser: Optional[KeyTabParser] = None

    def colour_text(self, text: str, colour: Any) -> str:
        """Apply colour to text if colours are enabled."""
        if self.use_colour:
            return f"{colour}{text}{Style.RESET_ALL}"
        return text

    def log_info(self, message: str) -> None:
        """Log an info message."""
        logger.info(message)
        print(self.colour_text(f"[+] {message}", Fore.GREEN))

    def log_warning(self, message: str) -> None:
        """Log a warning message."""
        logger.warning(message)
        print(self.colour_text(f"[!] {message}", Fore.YELLOW))

    def log_error(self, message: str) -> None:
        """Log an error message."""
        logger.error(message)
        print(self.colour_text(f"[!] {message}", Fore.RED))

    def log_debug(self, message: str) -> None:
        """Log a debug message if verbose is enabled."""
        logger.debug(message)
        if self.verbose:
            print(self.colour_text(f"[*] {message}", Fore.CYAN))

    def load_keytab(self) -> bool:
        """
        Load and validate the keytab file.

        Returns:
            bool: True if the file was successfully loaded, False otherwise
        """
        try:
            file_path = Path(self.keytab_path)

            # Check file existence and permissions
            if not file_path.exists():
                self.log_error(f"File '{self.keytab_path}' not found.")
                return False

            if not file_path.is_file():
                self.log_error(f"'{self.keytab_path}' is not a regular file.")
                return False

            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()

            # Check file size
            if len(data) > MAX_KEYTAB_SIZE:
                self.log_error(f"Keytab file exceeds maximum size of {MAX_KEYTAB_SIZE} bytes.")
                return False

            if len(data) < HEADER_SIZE:
                self.log_error("Keytab file is too small to be valid.")
                return False

            self.hex_encoded = binascii.hexlify(data).decode('utf-8')

            # Validate keytab version
            version = self.hex_encoded[:VERSION_FIELD_SIZE]
            if version not in SUPPORTED_VERSIONS:
                self.log_error(
                    f"Unsupported keytab version: {version}. "
                    f"Only versions {', '.join(SUPPORTED_VERSIONS)} are supported."
                )
                return False

            # Initialise data container and parser
            self.keytab_data = KeytabData(
                version=version,
                file_path=self.keytab_path
            )

            # Select appropriate parser
            if version == "0501":
                self.parser = KeyTabParserV0501()
            else:
                self.parser = KeyTabParserV0502()

            self.log_info(f"Keytab file '{self.keytab_path}' successfully loaded (version {version}).")
            return True

        except PermissionError:
            self.log_error(f"Permission denied when accessing '{self.keytab_path}'.")
            return False
        except Exception as e:
            self.log_error(f"Error loading keytab file: {str(e)}")
            return False

    def analyse_keytab(self) -> Dict[str, Any]:
        """
        Analyse the keytab file structure without extracting hashes.

        Returns:
            Dictionary with analysis results
        """
        analysis: Dict[str, Any] = {
            "version": self.keytab_data.version if self.keytab_data else "unknown",
            "file_size": len(self.hex_encoded) // 2 if self.hex_encoded else 0,
            "encryption_types": [],
            "entry_count": 0,
            "potential_principals": set()
        }

        # Detect encryption types
        for enc_id, enc_info in ENCRYPTION_TYPES.items():
            enc_pattern = f"{enc_id}{enc_info.pattern_suffix}"
            if enc_pattern in self.hex_encoded:
                analysis["encryption_types"].append(enc_info.name)

        # Count potential entries (rough estimate)
        analysis["entry_count"] = sum(
            self.hex_encoded.count(enc_type)
            for enc_type in ENCRYPTION_TYPES.keys()
        )

        return analysis

    def detect_encryption_types(self) -> Dict[str, bool]:
        """
        Detect supported encryption types in the keytab.

        Returns:
            Dict mapping encryption type IDs to boolean indicating presence
        """
        found_types: Dict[str, bool] = {}

        for enc_id, enc_info in ENCRYPTION_TYPES.items():
            enc_pattern = f"{enc_id}{enc_info.pattern_suffix}"
            if enc_pattern in self.hex_encoded:
                self.log_info(f"{enc_info.name} encryption detected. Will attempt to extract hash.")
                found_types[enc_id] = True
            else:
                self.log_debug(f"No {enc_info.name} encryption found.")
                found_types[enc_id] = False

        return found_types

    def verify_hash(self, enc_type: str, hash_value: str) -> bool:
        """
        Verify that a hash meets the expected format requirements.

        Args:
            enc_type: Encryption type ID
            hash_value: Hash value to verify

        Returns:
            bool: True if the hash is valid, False otherwise
        """
        # Check if encryption type is known
        if enc_type not in ENCRYPTION_TYPES:
            self.log_debug(f"Unknown encryption type: {enc_type}")
            return False

        # Check hash length
        expected_length = ENCRYPTION_TYPES[enc_type].hash_length
        if len(hash_value) != expected_length:
            self.log_debug(
                f"Invalid hash length for {ENCRYPTION_TYPES[enc_type].name}: "
                f"expected {expected_length}, got {len(hash_value)}"
            )
            return False

        # Check for valid hex characters
        try:
            bytes.fromhex(hash_value)
        except ValueError:
            self.log_debug(f"Invalid hex characters in hash: {hash_value}")
            return False

        return True

    def extract_entries(self) -> bool:
        """
        Extract all entries from the keytab file.

        Returns:
            bool: True if any entries were extracted, False otherwise
        """
        if self.dry_run:
            self.log_info("Dry-run mode: Analysing structure without extracting hashes")
            analysis = self.analyse_keytab()
            self.log_info(f"Analysis results:")
            self.log_info(f"  Version: {analysis['version']}")
            self.log_info(f"  File size: {analysis['file_size']} bytes")
            self.log_info(f"  Encryption types: {', '.join(analysis['encryption_types']) if analysis['encryption_types'] else 'None detected'}")
            self.log_info(f"  Estimated entries: {analysis['entry_count']}")
            return analysis['entry_count'] > 0

        if not self.parser or not self.keytab_data:
            self.log_error("Parser not initialised.")
            return False

        pointer = HEADER_SIZE
        entry_count = 0

        try:
            while pointer < len(self.hex_encoded):
                result, new_pointer = self.parser.extract_entry(self.hex_encoded, pointer)

                if result:
                    realm, principal, key_entry = result

                    # Verify hash before adding
                    if self.verify_hash(key_entry.encryption_type, key_entry.hash_value):
                        self.keytab_data.add_entry(realm, principal, key_entry)
                        entry_count += 1
                    else:
                        self.log_warning(
                            f"Invalid hash found for {principal}, type {key_entry.encryption_type}"
                        )

                if new_pointer <= pointer:
                    # Avoid infinite loop
                    self.log_warning(f"Parser stuck at position {pointer}. Stopping.")
                    break

                pointer = new_pointer

            self.log_info(f"Processed {entry_count} valid entries from keytab file.")
            return entry_count > 0

        except Exception as e:
            self.log_error(f"Error during extraction: {str(e)}")
            return False

    def format_output(self, output_file: Optional[str] = None) -> bool:
        """
        Format and display the extracted data.

        Args:
            output_file: Optional path to save results

        Returns:
            bool: True if successful, False otherwise
        """
        if self.dry_run:
            # Dry-run output is handled in extract_entries
            return True

        if not self.keytab_data or not self.keytab_data.principals:
            self.log_error("No valid entries found in keytab file.")
            return False

        output_lines: List[str] = []

        def add_line(line: str) -> None:
            output_lines.append(line)
            print(line)

        add_line("\n" + self.colour_text("=== KeyTabExtract Results ===", Fore.CYAN))
        add_line(f"File: {self.keytab_data.file_path}")
        add_line(f"Version: {self.keytab_data.version}")
        add_line("")

        # Sort principals for consistent output
        for principal_name in sorted(self.keytab_data.principals.keys()):
            principal = self.keytab_data.principals[principal_name]
            add_line(self.colour_text(f"Realm: {principal.realm}", Fore.MAGENTA))
            add_line(self.colour_text(f"  Service Principal: {principal.name}", Fore.BLUE))

            # Keys are already sorted by timestamp (newest first)
            for key in principal.keys:
                add_line(
                    self.colour_text(
                        f"    Timestamp: {key.timestamp_str} (KVNO: {key.kvno})",
                        Fore.YELLOW
                    )
                )

                # Get encryption info
                enc_info = ENCRYPTION_TYPES.get(key.encryption_type)
                display_name = enc_info.display if enc_info else f"Type-{key.encryption_type}"

                # Format hash
                formatted_hash = HashFormatter.format(
                    self.hash_format,
                    key.encryption_type,
                    key.hash_value,
                    principal.realm,
                    principal.name
                )

                add_line(f"      {display_name}: {formatted_hash}")

        # Save to file if requested
        if output_file:
            try:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)

                with open(output_path, 'w') as f:
                    for line in output_lines:
                        # Strip ANSI colour codes for file output
                        clean_line = re.sub(r'\x1b\[[0-9;]+m', '', line)
                        f.write(clean_line + "\n")

                self.log_info(f"Results saved to {output_file}")
                return True

            except Exception as e:
                self.log_error(f"Error saving to file: {str(e)}")
                return False

        return True

    def run(self, output_file: Optional[str] = None) -> int:
        """
        Main execution flow.

        Args:
            output_file: Optional path to save results

        Returns:
            int: Exit code (0 for success, non-zero for errors)
        """
        if not self.load_keytab():
            return 1

        if not self.detect_encryption_types():
            self.log_warning("No supported encryption types found.")
            return 1

        if not self.extract_entries():
            if not self.dry_run:
                self.log_error("Failed to extract entries from keytab file.")
            return 1

        if not self.format_output(output_file):
            return 1

        return 0


def process_directory(directory: str, args: argparse.Namespace) -> int:
    """
    Process all keytab files in a directory.

    Args:
        directory: Directory path to scan for keytab files
        args: Command line arguments

    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    dir_path = Path(directory)

    if not dir_path.is_dir():
        logger.error(f"Directory not found: {directory}")
        print(f"[!] Directory not found: {directory}")
        return 1

    success_count: int = 0
    failure_count: int = 0
    keytab_files: List[Path] = list(dir_path.rglob("*.keytab"))

    if not keytab_files:
        logger.warning(f"No .keytab files found in {directory}")
        print(f"[!] No .keytab files found in {directory}")
        return 1

    logger.info(f"Found {len(keytab_files)} keytab files in {directory}")
    print(f"[+] Found {len(keytab_files)} keytab files in {directory}")

    # Process each keytab file
    for filepath in keytab_files:
        print(f"\n[*] Processing {filepath}...")
        logger.info(f"Processing {filepath}")

        # Create output filename if needed
        output_file: Optional[str] = None
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = str(output_dir / f"{filepath.stem}.txt")

        extractor = KeyTabExtractor(
            str(filepath),
            verbose=args.verbose,
            no_colour=args.no_colour,
            hash_format=HashFormat(args.format),
            dry_run=args.dry_run
        )
        result = extractor.run(output_file)

        if result == 0:
            success_count += 1
        else:
            failure_count += 1

    logger.info(f"Batch processing complete: {success_count} successful, {failure_count} failed")
    print(f"\n[*] Batch processing complete: {success_count} successful, {failure_count} failed")
    return 0 if failure_count == 0 else 1


def setup_logging(log_file: Optional[str], log_level: str) -> None:
    """
    Configure logging.

    Args:
        log_file: Path to log file or None for console logging
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=numeric_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        # Configure a null handler if no log file is specified
        logging.basicConfig(
            level=numeric_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[logging.NullHandler()]
        )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="KeyTabExtract: Extract hashes from Kerberos keytab files with timestamps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s service.keytab
  %(prog)s -o hashes.txt service.keytab
  %(prog)s -v -f hashcat service.keytab
  %(prog)s -d /path/to/keytabs -o output_dir
  %(prog)s --log keytab.log --log-level DEBUG service.keytab
  %(prog)s --dry-run service.keytab  # Analyse without extracting
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("keytab", nargs="?", help="Path to the keytab file")
    input_group.add_argument(
        "-d", "--directory",
        help="Process all .keytab files in the specified directory"
    )

    parser.add_argument(
        "-o", "--output",
        help="Save results to the specified file or directory (for batch mode)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "hashcat", "john"],
        default="plain",
        help="Output format for hashes (plain, hashcat, or john)"
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable coloured output"
    )
    parser.add_argument(
        "--log",
        help="Log file path"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyse the keytab file structure without extracting hashes"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.keytab and not args.directory:
        parser.error("Either a keytab file or directory must be specified")

    return args


def main() -> int:
    """Main entry point for the script."""
    args = parse_arguments()

    # Setup logging
    setup_logging(args.log, args.log_level)
    logger.info(f"KeyTabExtract started with arguments: {vars(args)}")

    try:
        # Process directory or single file
        if args.directory:
            return process_directory(args.directory, args)
        else:
            extractor = KeyTabExtractor(
                args.keytab,
                verbose=args.verbose,
                no_colour=args.no_colour,
                hash_format=HashFormat(args.format),
                dry_run=args.dry_run
            )
            return extractor.run(args.output)

    except KeyboardInterrupt:
        logger.warning("Operation interrupted by user")
        print("\n[!] Operation interrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Unhandled exception: {str(e)}")
        print(f"[!] Error: {str(e)}")
        return 1
    finally:
        logger.info("KeyTabExtract finished")


if __name__ == "__main__":
    sys.exit(main())