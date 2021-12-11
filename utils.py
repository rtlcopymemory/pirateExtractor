import os
import sys
import json
import re
import subprocess
from typing import BinaryIO, TextIO


PE_SIGN = b"\x4d\x5a"

src_dir = "src/"


def is_PE(file: BinaryIO) -> bool:
    pos = file.tell()
    # A whence value of 0 measures from the beginning of the file,
    # 1 uses the current file position,
    # and 2 uses the end of the file as the reference point
    file.seek(0, 0)
    signature = file.read(len(PE_SIGN))
    file.seek(pos, 0)
    return signature == PE_SIGN


def matches_bytes(file: BinaryIO, sign: bytes) -> bool:
    pos = file.tell()
    block = file.read(len(sign))
    file.seek(pos)
    return block == sign


def find_block_pos(file: BinaryIO, sign: bytes, start: int = 0) -> int:
    pos = file.tell()
    file.seek(start, 0)

    position = None

    while file.read(1) != b'':
        if matches_bytes(file, sign):
            position = file.tell()
            break

    file.seek(pos, 0)
    return position


def extract_json(file: BinaryIO, start: int) -> dict:
    """
    This function wants as input the while exe file (binary)
    and the start index for the nodejs section
    """
    pos = file.tell()
    file.seek(start, 0)

    parenthesis = 0
    # reach the json from beginning
    while parenthesis != 2:
        byte = file.read(1)
        if byte == b'{':
            parenthesis += 1
        elif byte == b'}':
            parenthesis -= 1

    # go back 1 to include the beginning
    file.seek(-1, 1)
    parenthesis = 0

    string = ""
    if file.read(1) != b"{":
        print("Something went wrong in extract_json()", file=sys.stderr)
        return None
    string = "{"
    parenthesis = 1

    while parenthesis > 0:
        byte = file.read(1)
        string += byte.decode()

        if byte == b'{':
            parenthesis += 1
        elif byte == b'}':
            parenthesis -= 1

    file.seek(pos, 0)
    return json.loads(string)


def extract_files(file: BinaryIO, files: dict, zero_offset: int, out_dir: str = "./out/") -> int:
    """
    Returns the type of file structure (where the main is)
    0: /out/src (generated)
    1: /out/builds
    """
    if "resources" not in files.keys():
        print("resources key not found in files dictionary", file=sys.stderr)
        return -2

    kind = 1

    os.makedirs(out_dir, exist_ok=True)
    pwd = os.getcwd()
    os.chdir(out_dir)

    save_files_json(files)

    n_childs = 0
    if "builds" not in list(files["resources"].keys())[0]:
        n_childs = 1
        kind = 0
        os.makedirs(src_dir, exist_ok=True)
        os.chdir(src_dir)
        # ./out/src

    for key in files["resources"]:
        # Each key is a file
        offset, length = files["resources"][key]

        key = key.replace("\\", "/")
        key = key.replace("\\", "/")
        key = key.replace("//", "/")

        prepare_dir(key, n_childs)
        out_file: BinaryIO = open(key, "wb+")

        file.seek(zero_offset + offset, 0)
        file_bytes = file.read(length)
        out_file.write(file_bytes)

        out_file.close()

    os.chdir(pwd)
    return kind


def prepare_dir(file_path: str, n_childs: int):
    dirs = file_path.split("/")[:-1]
    parents = dirs.count("..")
    if parents > n_childs:
        print(" [WARN] Possible file creation outside of the out folder detected!")

    os.makedirs("/".join(dirs), exist_ok=True)


def save_files_json(files: dict):
    with open(f"file_structure.json", "w+") as f:
        f.write(json.dumps(files, indent=2))


def get_eval_code(main_path: str) -> str:
    with open(main_path, "rb") as f:
        pos = find_block_pos(f, b"new Webhook") + len(b"new Webhook")

        f.seek(pos, 0)
        result = ""

        if f.read(1) != b"(":
            return None

        parenthesis = 1
        while parenthesis > 0:
            byte = f.read(1)

            if byte == b"(":
                parenthesis += 1
            elif byte == b")":
                parenthesis -= 1

            result += byte.decode()

        return result[:-1]


def get_injection_point(file: TextIO, kind: int):
    pos = file.tell()

    n_instructions = 2
    if kind == 1:
        n_instructions = 3

    parenthesis = 0
    semicolumns = 0

    while semicolumns < n_instructions:
        char = file.read(1)
        if char == "":
            raise Exception("Fatal error while finding injection point")

        if char == "(":
            parenthesis += 1
        elif char == ")":
            parenthesis -= 1

        if char == ";" and parenthesis == 0:
            semicolumns += 1

    res = file.tell()
    file.seek(pos, 0)
    return res


def inject(main_path: str, payload: str, kind: int):
    new_path = main_path + ".new"
    with open(main_path, "r") as old_f:
        with open(new_path, "w") as new_f:
            pos = get_injection_point(old_f, kind)
            new_f.write(old_f.read(pos))
            new_f.write(payload)
            new_f.write(old_f.read())

    os.remove(main_path)
    os.rename(new_path, main_path)


def execute_node(root_dir: str, entrypoint: str) -> str:
    os.chdir(root_dir)
    return subprocess.getoutput(f"node {entrypoint}")


def is_simple(path: str):
    out = subprocess.getstatusoutput(
        f"strings {path} | grep -e https://.*/webhook")

    if out[0] == 0:
        print(out[1])

    return out[0] == 0
