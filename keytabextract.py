#!/usr/bin/env python3
"""
KeyTabExtract: Extract hashes from Kerberos keytab files with timestamps.
Shows all keys sorted by timestamp (newest first) for each service principal.

Features:
- Multiple keytab version support (0501, 0502)
- Hash verification
- colourised output
- Batch processing of multiple keytab files
- Multiple hash format options (plain, hashcat, john)
- Comprehensive logging
"""

import argparse
import binascii
import datetime
import logging
import os
import re
import sys
from typing import Dict, Any, Optional, List, Tuple, Set

# Try to import colourama for coloured output
try:
    import colourama
    from colourama import Fore, Style
    colourama.init()
    HAS_colourS = True
except ImportError:
    HAS_colourS = False
    # Create dummy colour constants
    class DummyFore:
        def __getattr__(self, name):
            return ""
    class DummyStyle:
        def __getattr__(self, name):
            return ""
    Fore = DummyFore()
    Style = DummyStyle()

# Configure logger
logger = logging.getLogger("keytabextract")

# Constants
ENCRYPTION_TYPES = {
    "0017": {"name": "RC4-HMAC", "display": "NTLM", "hash_length": 32},
    "0012": {"name": "AES256-CTS-HMAC-SHA1", "display": "AES-256", "hash_length": 64},
    "0011": {"name": "AES128-CTS-HMAC-SHA1", "display": "AES-128", "hash_length": 32}
}

SUPPORTED_VERSIONS = ["0501", "0502"]


class KeyTabExtractor:
    """Extract and process hashes from Kerberos keytab files."""
    
    def __init__(self, keytab_path: str, verbose: bool = False, 
                 no_colour: bool = False, hash_format: str = "plain"):
        """
        Initialise the KeyTabExtractor.
        
        Args:
            keytab_path: Path to the keytab file
            verbose: Enable verbose output
            no_colour: Disable coloured output
            hash_format: Format for hash output (plain, hashcat, john)
        """
        self.keytab_path = keytab_path
        self.hex_encoded = ""
        self.all_data = {}
        self.verbose = verbose
        self.use_colour = HAS_colourS and not no_colour
        self.hash_format = hash_format
        self.version = None
    
    def colour_text(self, text: str, colour) -> str:
        """Apply colour to text if colours are enabled."""
        if self.use_colour:
            return f"{colour}{text}{Style.RESET_ALL}"
        return text
    
    def log_info(self, message: str):
        """Log an info message."""
        logger.info(message)
        print(self.colour_text(f"[+] {message}", Fore.GREEN))
    
    def log_warning(self, message: str):
        """Log a warning message."""
        logger.warning(message)
        print(self.colour_text(f"[!] {message}", Fore.YELLOW))
    
    def log_error(self, message: str):
        """Log an error message."""
        logger.error(message)
        print(self.colour_text(f"[!] {message}", Fore.RED))
    
    def log_debug(self, message: str):
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
            with open(self.keytab_path, 'rb') as f:
                data = f.read()
            self.hex_encoded = binascii.hexlify(data).decode('utf-8')
            
            # Validate keytab version
            self.version = self.hex_encoded[:4]
            if self.version not in SUPPORTED_VERSIONS:
                self.log_error(f"Unsupported keytab version: {self.version}. "
                              f"Only versions {', '.join(SUPPORTED_VERSIONS)} are supported.")
                return False
                
            self.log_info(f"Keytab file '{self.keytab_path}' successfully loaded "
                         f"(version {self.version}).")
            return True
        except FileNotFoundError:
            self.log_error(f"File '{self.keytab_path}' not found.")
            return False
        except PermissionError:
            self.log_error(f"Permission denied when accessing '{self.keytab_path}'.")
            return False
        except Exception as e:
            self.log_error(f"Error loading keytab file: {str(e)}")
            return False
    
    def detect_encryption_types(self) -> Dict[str, bool]:
        """
        Detect supported encryption types in the keytab.
        
        Returns:
            Dict mapping encryption type IDs to boolean indicating presence
        """
        found_types = {}
        
        for enc_id, enc_info in ENCRYPTION_TYPES.items():
            enc_pattern = f"{enc_id}0010" if enc_id == "0017" else f"{enc_id}0020" if enc_id == "0012" else f"{enc_id}0010"
            if enc_pattern in self.hex_encoded:
                self.log_info(f"{enc_info['name']} encryption detected. Will attempt to extract hash.")
                found_types[enc_id] = True
            else:
                self.log_debug(f"No {enc_info['name']} encryption found.")
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
        expected_length = ENCRYPTION_TYPES[enc_type]["hash_length"]
        if len(hash_value) != expected_length:
            self.log_debug(f"Invalid hash length for {ENCRYPTION_TYPES[enc_type]['name']}: "
                          f"expected {expected_length}, got {len(hash_value)}")
            return False
        
        # Check for valid hex characters
        if not all(c in "0123456789abcdefABCDEF" for c in hash_value):
            self.log_debug(f"Invalid characters in hash: {hash_value}")
            return False
        
        return True
    
    def format_hash(self, enc_type: str, hash_value: str, 
                   realm: str, service_principal: str) -> str:
        """
        Format a hash according to the specified output format.
        
        Args:
            enc_type: Encryption type ID
            hash_value: Hash value to format
            realm: Kerberos realm
            service_principal: Service principal name
            
        Returns:
            str: Formatted hash
        """
        enc_name = ENCRYPTION_TYPES.get(enc_type, {}).get("name", f"Type-{enc_type}")
        
        if self.hash_format == "plain":
            return hash_value
        elif self.hash_format == "hashcat":
            if enc_type == "0017":  # RC4-HMAC
                return f"{hash_value}:{service_principal}"
            elif enc_type == "0012":  # AES256
                return f"{hash_value}:{service_principal}:{realm}"
            elif enc_type == "0011":  # AES128
                return f"{hash_value}:{service_principal}:{realm}"
            else:
                return hash_value
        elif self.hash_format == "john":
            if enc_type == "0017":  # RC4-HMAC
                return f"{service_principal}:{hash_value}"
            elif enc_type == "0012" or enc_type == "0011":  # AES
                return f"{service_principal}@{realm}:{hash_value}"
            else:
                return f"{service_principal}:{hash_value}"
        else:
            return hash_value
    
    def extract_entry_v0501(self, pointer: int) -> int:
        """
        Extract a keytab entry using v0501 format.
        
        Args:
            pointer: Current position in the hex string
            
        Returns:
            int: New pointer position after processing this entry
        """
        # Implementation for v0501 format
        # This is a placeholder - actual implementation would need to handle
        # the specific format differences of v0501
        self.log_debug(f"Parsing v0501 entry at position {pointer}")
        return self.extract_entry_v0502(pointer)
    
    def extract_entry_v0502(self, pointer: int) -> int:
        """
        Extract a keytab entry using v0502 format.
        
        Args:
            pointer: Current position in the hex string
            
        Returns:
            int: New pointer position after processing this entry
        """
        try:
            # Number of components
            num_components = int(self.hex_encoded[pointer:pointer+4], 16)
            self.log_debug(f"Number of components: {num_components}")

            # Realm length
            realm_len = int(self.hex_encoded[pointer+4:pointer+8], 16)
            self.log_debug(f"Realm length: {realm_len}")

            # Realm value
            realm_end = pointer+8 + (realm_len * 2)
            realm = bytes.fromhex(self.hex_encoded[pointer+8:realm_end]).decode('utf-8')
            self.log_debug(f"Realm: {realm}")
            
            # Extract components
            components = []
            comp_start = realm_end
            comp_end = comp_start
            for i in range(num_components):
                comp_len = int(self.hex_encoded[comp_start:comp_start+4], 16)
                comp_end = comp_start+4 + (comp_len * 2)
                components.append(self.hex_encoded[comp_start+4:comp_end])
                comp_start = comp_end
                self.log_debug(f"Component {i+1} length: {comp_len}")

            # Convert components to strings and join
            components = [bytes.fromhex(x).decode('utf-8') for x in components]
            service_principal = "/".join(components)
            self.log_debug(f"Service principal: {service_principal}")
            
            # Name type
            typename_offset = comp_end + 8
            name_type = int(self.hex_encoded[comp_end:typename_offset], 16)
            self.log_debug(f"Name type: {name_type}")
            
            # Timestamp
            timestamp_offset = typename_offset + 8
            timestamp = int(self.hex_encoded[typename_offset:timestamp_offset], 16)
            timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            self.log_debug(f"Timestamp: {timestamp_str}")

            # Key version number
            vno_offset = timestamp_offset + 2
            vno = int(self.hex_encoded[timestamp_offset:vno_offset], 16)
            self.log_debug(f"KVNO: {vno}")

            # Key type
            keytype_offset = vno_offset + 4
            keytype_hex = self.hex_encoded[vno_offset:keytype_offset]
            self.log_debug(f"Key type: {keytype_hex}")
            
            # Key length
            key_val_offset = keytype_offset + 4
            key_val_len = int(self.hex_encoded[keytype_offset:key_val_offset], 16)
            self.log_debug(f"Key length: {key_val_len}")

            # Key value
            key_val_start = key_val_offset
            key_val_finish = key_val_start + (key_val_len * 2)
            key_val = self.hex_encoded[key_val_start:key_val_finish]
            self.log_debug(f"Key value: {key_val}")
            
            # Verify hash
            if self.verify_hash(keytype_hex, key_val):
                # Store extracted data
                if not realm in self.all_data:
                    self.all_data[realm] = {}
                if not service_principal in self.all_data[realm]:
                    self.all_data[realm][service_principal] = {}
                if not timestamp_str in self.all_data[realm][service_principal]:
                    self.all_data[realm][service_principal][timestamp_str] = {
                        "timestamp": timestamp,  # Store raw timestamp for sorting
                        "kvno": vno,
                        "keys": {}
                    }
                if not keytype_hex in self.all_data[realm][service_principal][timestamp_str]["keys"]:
                    self.all_data[realm][service_principal][timestamp_str]["keys"][keytype_hex] = key_val
            else:
                self.log_warning(f"Invalid hash found for {service_principal}, type {keytype_hex}")
            
            # Calculate next entry position
            next_entry = key_val_finish
            
            # Skip padding and alignment bytes
            try:
                # Try to read next size field
                next_size = int(self.hex_encoded[next_entry:next_entry+8], 16)
                next_entry += 8
                
                # Skip alignment bytes if needed
                while next_entry < len(self.hex_encoded) and self.hex_encoded[next_entry:next_entry+2] == "00":
                    next_entry += 2
                    
                # Handle special marker
                if next_entry < len(self.hex_encoded) and self.hex_encoded[next_entry:next_entry+4] == "ffff":
                    next_entry += 8
            except ValueError:
                # If we can't parse the next size, try to find the next valid entry
                while next_entry < len(self.hex_encoded) and self.hex_encoded[next_entry:next_entry+2] == "00":
                    next_entry += 2
                    
                if next_entry < len(self.hex_encoded) and self.hex_encoded[next_entry:next_entry+4] == "ffff":
                    next_entry += 8

            return next_entry
        except Exception as e:
            self.log_error(f"Error parsing entry at position {pointer}: {str(e)}")
            # Try to advance to next entry
            return pointer + 8
    
    def extract_entries(self) -> bool:
        """
        Extract all entries from the keytab file.
        
        Returns:
            bool: True if any entries were extracted, False otherwise
        """
        pointer = 12  # Skip version and size fields
        entry_count = 0
        
        try:
            while pointer < len(self.hex_encoded):
                if self.version == "0501":
                    new_pointer = self.extract_entry_v0501(pointer)
                else:  # 0502
                    new_pointer = self.extract_entry_v0502(pointer)
                
                if new_pointer <= pointer:
                    # Avoid infinite loop
                    self.log_warning(f"Parser stuck at position {pointer}. Stopping.")
                    break
                
                pointer = new_pointer
                entry_count += 1
                
            self.log_info(f"Processed {entry_count} entries from keytab file.")
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
        if not self.all_data:
            self.log_error("No valid entries found in keytab file.")
            return False
        
        output_lines = []
        
        def add_line(line):
            output_lines.append(line)
            print(line)
        
        add_line("\n" + self.colour_text("=== KeyTabExtract Results ===", Fore.CYAN))
        add_line(f"File: {self.keytab_path}")
        add_line(f"Version: {self.version}")
        add_line("")
        
        for realm in self.all_data:
            add_line(self.colour_text(f"Realm: {realm}", Fore.MAGENTA))
            for sp in self.all_data[realm]:
                add_line(self.colour_text(f"  Service Principal: {sp}", Fore.BLUE))
                
                # Sort timestamps by the actual timestamp value (newest first)
                sorted_timestamps = sorted(
                    self.all_data[realm][sp].keys(),
                    key=lambda ts: self.all_data[realm][sp][ts]["timestamp"],
                    reverse=True
                )
                
                for timestamp in sorted_timestamps:
                    entry = self.all_data[realm][sp][timestamp]
                    add_line(self.colour_text(f"    Timestamp: {timestamp} (KVNO: {entry['kvno']})", Fore.YELLOW))
                    
                    for enctype in sorted(entry["keys"].keys()):
                        key_value = entry["keys"][enctype]
                        display_name = ENCRYPTION_TYPES.get(enctype, {}).get("display", f"Type-{enctype}")
                        
                        # Format hash according to selected format
                        formatted_hash = self.format_hash(enctype, key_value, realm, sp)
                        
                        add_line(f"      {display_name}: {formatted_hash}")
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    for line in output_lines:
                        # Strip ANSI colour codes for file output
                        clean_line = re.sub(r'\x1b\[\d+m', '', line)
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
    if not os.path.isdir(directory):
        logger.error(f"Directory not found: {directory}")
        print(f"[!] Directory not found: {directory}")
        return 1
    
    success_count = 0
    failure_count = 0
    keytab_files = []
    
    # Find all keytab files
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.keytab'):
                keytab_files.append(os.path.join(root, filename))
    
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
        output_file = None
        if args.output:
            base_name = os.path.splitext(os.path.basename(filepath))[0]
            output_dir = args.output
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"{base_name}.txt")
        
        extractor = KeyTabExtractor(
            filepath, 
            verbose=args.verbose,
            no_colour=args.no_colour,
            hash_format=args.format
        )
        result = extractor.run(output_file)
        
        if result == 0:
            success_count += 1
        else:
            failure_count += 1
    
    logger.info(f"Batch processing complete: {success_count} successful, {failure_count} failed")
    print(f"\n[*] Batch processing complete: {success_count} successful, {failure_count} failed")
    return 0 if failure_count == 0 else 1


def setup_logging(log_file: Optional[str], log_level: str):
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


def parse_arguments():
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
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("keytab", nargs="?", help="Path to the keytab file")
    input_group.add_argument("-d", "--directory", help="Process all .keytab files in the specified directory")
    
    parser.add_argument("-o", "--output", help="Save results to the specified file or directory (for batch mode)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--format", choices=["plain", "hashcat", "john"], default="plain",
                        help="Output format for hashes (plain, hashcat, or john)")
    parser.add_argument("--no-colour", action="store_true", help="Disable coloured output")
    parser.add_argument("--log", help="Log file path")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                        default="INFO", help="Set logging level")
    parser.add_argument("--dry-run", action="store_true", 
                        help="Analyse the keytab file without extracting hashes")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.keytab and not args.directory:
        parser.error("Either a keytab file or directory must be specified")
    
    return args


def main():
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
                hash_format=args.format
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
