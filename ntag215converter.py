"""
ntag215convert.py
2023-11-14
Modified ntag215 Flipper Conversion Code

Original Code by Turbospok

Execute with python ntag215converter -h to see options
"""
import argparse
import logging
import os
import pathlib
from typing import Tuple


def write_output(name: str, assemble: str, out_dir: str):
    """
    Handles writing the converted file
    :param name: The base filename - e.g. for Foo.bin, Foo
    :param assemble: The converted flipper-compatible contents
    :param out_dir: The directory to place Foo.nfc in
    """
    with open(os.path.join(out_dir, f"{name}.nfc"), "wt") as f:
        f.write(assemble)


def convert(contents: bytes) -> Tuple[str, int]:
    """
    Convert from bytes into the Page-based format expected by flipper

    Each "Page" is 4 bytes hex, notated like:
        Page 0: DE AD BE EF

    To process, we grab one byte at a time, turn it into a hex string, and store it in `page`.
    When page is "full" (has 4 bytes in it), we flush it to the buffer.

    When all's said and done, buffer contains text ready for writing to the end of a .nfc file.

    Also tracks and returns running page number, since that's also needed.
    There should be exacly 135 pages for the .nfc not to fail on flipper,
    due to NTAG215 beeing of 540 byte (135 pages) capacity.
    :param contents: byte array we're reading, from a .bin file
    :return: The full string of Pages, suitable for writing to a file
    """
    buffer = []
    page_count = 0

    page = []
    for i in range(len(contents)):
        if page_count > 132:
            logging.debug(f"We have enough pages, breaking")
            break

        byte = contents[i : i + 1].hex()
        page.append(byte)

        if len(page) == 4:
            buffer.append(f"Page {page_count}: {' '.join(page).upper()}")
            page = []
            page_count += 1

    # we may have an unfilled page. This needs to be filled out and appended
    if len(page) > 0:
        logging.debug(f"We have an unfilled final page: {page} with length {len(page)}")
        # pad with zeroes
        for i in range(len(page) - 1, 3):
            page.append("00")
        buffer.append(f"Page {page_count}: {' '.join(page).upper()}")
        page_count += 1

    # we are missing a few pages, padding with zeroes
    if page_count < 133:
        logging.debug(f"We are missing {133-page_count} pages, padding with zeroes")
        while page_count < 133:
            buffer.append(f"Page {page_count}: 00 00 00 00")
            page_count += 1

    # now add pages 133 (PWD) and 134 (PACK + RFUI / Reserved for future use)
    pwd_hex = ' '.join('{:02X}'.format(byte) for byte in get_pwd(contents))
    # PWD
    buffer.append(f"Page {page_count}: {pwd_hex}")
    page_count += 1
    # PACK (0x80 0x80) + RFUI (0x00 0x00)
    buffer.append(f"Page {page_count}: 80 80 00 00")
    page_count += 1

    return "\n".join(buffer), page_count


def get_uid(contents: bytes) -> str:
    """
    the UID appears to be made up of the first 3 bytes, a byte is skipped, and then the next 4 bytes
    :param contents: The bytes object we're operating on
    :return: something like `23 20 41 6D 69 69 62 6F`
    """
    page = []
    for i in range(3):
        byte = contents[i : i + 1].hex()
        page.append(byte)
    for i in range(4, 8):
        byte = contents[i : i + 1].hex()
        page.append(byte)

    return " ".join(page).upper()

def get_pwd(contents: bytes) -> bytes:
    """Return the PWD associated to the content UID"""
    uid = bytes.fromhex(get_uid(contents))
    #pwd = bytearray(4)    
    pwd = calculate_password(uid)

    return bytes(pwd)

def calculate_password(uid : bytearray):
    pwd = []
    if(len(uid) == 7):
        pwd.append(uid[1] ^ uid[3] ^ 0xAA)
        pwd.append(uid[2] ^ uid[4] ^ 0x55)
        pwd.append(uid[3] ^ uid[5] ^ 0xAA)
        pwd.append(uid[4] ^ uid[6] ^ 0x55)
        logging.debug(f"Password {''.join(' {:02X}'.format(x) for x in pwd) } generated")
    else:
        logging.error("Can not generate password! UID length not equal to 7")
    return pwd

def assemble_code(contents: {hex}) -> str:
    """
    Convert from .bin files to Flipper text-like .nfc files
    
    :param contents: File contents upon which .hex() can be called
    :return: A string to be written to a file
    """
    conversion, page_count = convert(contents)

    return f"""Filetype: Flipper NFC device
Version: 2
# Nfc device type can be UID, Mifare Ultralight, Bank card
Device type: NTAG215
# UID, ATQA and SAK are common for all formats
UID: {get_uid(contents)}
ATQA: 44 00
SAK: 00
# Mifare Ultralight specific data
Signature: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Mifare version: 00 04 04 02 01 00 11 03
Counter 0: 0
Tearing 0: 00
Counter 1: 0
Tearing 1: 00
Counter 2: 0
Tearing 2: 00
Pages total: {page_count}
{conversion}
"""

def get_string_containing(lines, sub_str):
    '''
    Searches a string by pattern
    :param lines: .nfc file content
    :param sub_str: Prefix for this line
    '''
    match = [s for s in lines if sub_str in s]
    return match[0]

def get_uid_string(lines):
    '''
    Returns line with UID
    :param lines: .nfc file content
    '''
    uid = get_string_containing(lines, "UID:")
    return uid

def get_uid_bytes(uid_str: str):
    '''
    Converts UID string data to byte array
    :param uid_str: string representation of UID
    '''
    symbols = uid_str.removeprefix("UID:").strip().removesuffix("\n")
    uid = bytearray.fromhex(symbols) 
    return uid

def format_new_page(suffix, data):
    hexData = ''.join(' {:02X}'.format(x) for x in data)
    return suffix + hexData + '\n'

def replace_page_data(lines, page_prefix, data):
    '''
    Searches line by prefix in file read by lines, then replaces all the data in it
    :param lines: .nfc file content
    :param page_prefix: page text prefix
    :param data: new data to replace
    '''
    str = get_string_containing(lines, page_prefix)
    i = lines.index(str)
    lines.pop(i)
    str = format_new_page(page_prefix, data)
    lines.insert(i, str)

def save_pwd_to_page(lines, pwd):
    '''
    Saves Password data to appropriate page in the .nfc file
    :param lines: .nfc file content
    :param pwd: password data
    '''
    replace_page_data(lines, "Page 133:", pwd)

def save_pack_to_page(lines, pack):
    '''
    Saves PACK data to appropriate page in the .nfc file
    :param lines: .nfc file content
    :param pack: pack data
    '''
    replace_page_data(lines, "Page 134:", [pack[0], pack[1], 0, 0])

def save_ntag215_v2_with_pwd(current_ntag215_path, new_ntag215_path):
     '''
     Opens .nfc files calculates password and PACK and saves to new location
     :param current_ntag215_path: path to current .nfc file
     :param new_ntag215_path: path to save new .nfc file with password
     '''
     with open(current_ntag215_path, "r") as file:
        lines = file.readlines()

        uid = get_uid_bytes(get_uid_string(lines))
        pwd = calculate_password(uid)

        save_pwd_to_page(lines, pwd)            
        save_pack_to_page(lines, [0x80, 0x80])

        with open(new_ntag215_path, "w+") as f_new:
            f_new.writelines(lines)

def convert_file(input_path: str, output_path: str):
    """
    Handles reading, converting, and writing a single file
    :param input_path: The full path to the .bin file
    :param output_path: The base directory to output to
    """
    input_extension = os.path.splitext(input_path)[1]
    if input_extension == ".bin":
        logging.info(f"Writing: {os.path.join(output_path, os.path.splitext(os.path.basename(input_path))[0])}.nfc")
        with open(input_path, "rb") as file:
            contents = file.read()
            name = os.path.split(input_path)[1]
            write_output(name.split(".bin")[0], assemble_code(contents), output_path)

    elif input_extension == ".nfc":
        name = os.path.split(input_path)[1]
        output_path = os.path.join(output_path, name)
        save_ntag215_v2_with_pwd(input_path, output_path)
    else:
        logging.info(f"{input_path} doesn't seem like a relevant file, skipping")


def process(path: str, output_path: str, tree: bool):
    """
    Process an input file, or walk through an input directory and process every matching .bin file therein
    :param path: Path to a single file or a directory containing one or more .bin files
    :param output_path: The base directory to output to
    """
    if os.path.isfile(path):
        convert_file(path, output_path)
    else:
        if tree:
            new_output_path = os.path.join(output_path, pathlib.Path(*pathlib.Path(path).parts[1:]))
            os.makedirs(new_output_path, exist_ok=True)
        else:
            new_output_path = output_path
        for filename in os.listdir(path):
            new_path = os.path.join(path, filename)
            logging.debug(f"Current file: {filename}; Current path: {new_path}")

            if os.path.isfile(new_path):
                convert_file(new_path, new_output_path)
            else:
                logging.debug(f"Recursing into: {new_path}")
                process(new_path, output_path, tree)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input-path",
        required=True,
        type=pathlib.Path,
        help="Single file or directory tree to convert.",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        required=False,
        type=pathlib.Path,
        help="Directory to store output in. Will be created if it doesn't exist. If not specified, the output will be "
        "stored in the same location as the original, with a '.nfc' extension.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Show extra info: pass -v to see what's going on, pass -vv to get useful debug info.",
    )
    parser.add_argument(
        "-t",
        "--tree",
        action="store_true",
        default=False,
        help="Keep the same folder structure from the input folder to the output folder.",
    )
    args = parser.parse_args()
    if args.verbose >= 2:
        # set debug
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose >= 1:
        # set info
        logging.basicConfig(level=logging.INFO)
    logging.debug(f"Parsed args into {args}")
    return args


def main():
    args = get_args()

    # single file mode
    if os.path.isfile(args.input_path):
        if not args.output_path:
            args.output_path = os.path.split(args.input_path)[0]
    # recursive directory mode
    elif os.path.isdir(args.input_path):
        if not args.output_path:
            logging.exception(
                ValueError(
                    f"{args.input_path} is a directory, but no output path given."
                )
            )
        logging.debug(f"Going to create output directory {args.output_path}")
        os.makedirs(args.output_path, exist_ok=True)
    elif not os.path.exists(args.input_path):
        logging.exception(
            FileNotFoundError(f"{args.input_path} doesn't actually exist")
        )

    logging.debug(f"input: {args.input_path}, output: {args.output_path}")
    process(args.input_path, args.output_path, args.tree)


if __name__ == "__main__":
    main()
    print("----Good Execution----")