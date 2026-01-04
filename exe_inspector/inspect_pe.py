import argparse
import hashlib
import math
import os
from typing import Dict, Any, List

import pefile


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return ent


def detect_arch(pe: pefile.PE) -> str:
    machine = pe.FILE_HEADER.Machine
    machine_map = {
        0x014C: "x86",
        0x8664: "x64",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0xAA64: "ARM64",
    }
    return machine_map.get(machine, f"unknown(0x{machine:04X})")


def detect_pe_kind(pe: pefile.PE) -> str:
    magic = pe.OPTIONAL_HEADER.Magic
    if magic == 0x10B:
        return "PE32"
    if magic == 0x20B:
        return "PE32+"
    return f"unknown(0x{magic:04X})"


def read_section_bytes(path: str, pe: pefile.PE, section) -> bytes:
    with open(path, "rb") as f:
        f.seek(section.PointerToRawData)
        return f.read(section.SizeOfRawData)


def analyze_sections(path: str, pe: pefile.PE) -> List[Dict[str, Any]]:
    out = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        raw_size = int(s.SizeOfRawData)
        raw_ptr = int(s.PointerToRawData)
        virt_size = int(getattr(s, "Misc_VirtualSize", 0))
        chars = int(s.Characteristics)

        data = read_section_bytes(path, pe, s) if raw_size > 0 else b""
        ent = shannon_entropy(data)

        out.append(
            {
                "name": name,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "virtual_size": virt_size,
                "entropy": round(ent, 4),
                "characteristics_hex": f"0x{chars:08X}",
            }
        )
    return out


def is_pe_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            mz = f.read(2)
        return mz == b"MZ"
    except OSError:
        return False

def extract_imports(pe: pefile.PE) -> Dict[str, List[str]]:
    imports: Dict[str, List[str]] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        funcs: List[str] = []
        for imp in entry.imports:
            if imp.name:
                if imp.name:
                    funcs.append(imp.name.decode(errors="replace"))
                else:
                    funcs.append(f"ordinal_{imp.ordinal}")
        imports[dll] = funcs
    return imports

def map_capabilities(imports: Dict[str, List[str]]) -> List[str]:
    caps = set()

    dlls = {d.lower() for d in imports.keys()}
    all_funcs = set()
    for d, fs in imports.items():
        for f in fs:
            all_funcs.add(f.lower())

    # DLL-based signals
    if any(d in dlls for d in ["ws2_32.dll", "wininet.dll", "winhttp.dll"]):
        caps.add("network")
    if any(d in dlls for d in ["advapi32.dll"]):
        caps.add("registry-and-services")
    if any(d in dlls for d in ["crypt32.dll", "bcrypt.dll"]):
        caps.add("crypto")
    if any(d in dlls for d in ["shell32.dll", "shlwapi.dll"]):
        caps.add("shell-and-path-handling")
    if any(d in dlls for d in ["msi.dll"]):
        caps.add("msi-installer-apis")

    # Function-based signals
    if any(f in all_funcs for f in ["createprocessa", "createprocessw", "shellexecutew"]):
        caps.add("process-launch")
    if any(f in all_funcs for f in ["regcreatekeyexa", "regcreatekeyexw", "regsetvalueexa", "regsetvalueexw"]):
        caps.add("registry-write")
    if any(f in all_funcs for f in ["urldownloadtofilea", "urldownloadtofilew"]):
        caps.add("download")
    if any(f in all_funcs for f in ["winexec"]):
        caps.add("process-launch")

    return sorted(caps)


def main() -> None:
    ap = argparse.ArgumentParser(description="Static PE inspector (Milestones 1 and 2)")
    ap.add_argument("path", help="Path to .exe or .dll")
    args = ap.parse_args()

    path = args.path
    if not os.path.isfile(path):
        raise SystemExit(f"File not found: {path}")

    if not is_pe_file(path):
        raise SystemExit("Not a PE file. Missing MZ header.")

    file_size = os.path.getsize(path)
    file_hash = sha256_file(path)

    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError as e:
        raise SystemExit(f"PE parse failed: {e}")

    report: Dict[str, Any] = {
        "path": os.path.abspath(path),
        "file_size": file_size,
        "sha256": file_hash,
        "pe_kind": detect_pe_kind(pe),
        "arch": detect_arch(pe),
        "compile_time_unix": int(pe.FILE_HEADER.TimeDateStamp),
        "num_sections": int(pe.FILE_HEADER.NumberOfSections),
        "sections": analyze_sections(path, pe),
    }

    print("File")
    print(f"  Path: {report['path']}")
    print(f"  Size: {report['file_size']} bytes")
    print(f"  SHA-256: {report['sha256']}")
    print()
    print("PE")
    print(f"  Kind: {report['pe_kind']}")
    print(f"  Arch: {report['arch']}")
    print(f"  Sections: {report['num_sections']}")
    print()
    print("Sections (name, raw_size, entropy)")
    for s in report["sections"]:
        print(f"  {s['name']:<10}  {s['raw_size']:<10}  {s['entropy']}")

    imports = extract_imports(pe)
    caps = map_capabilities(imports)

    report["imports"] = imports
    report["capabilities"] = caps

    print()
    print("Imports (DLL count, function count)")
    dll_count = len(imports)
    func_count = sum(len(v) for v in imports.values())
    print(f"  DLLs: {dll_count}")
    print(f"  Functions: {func_count}")

    print()
    print("Imported DLLs")
    for d in sorted(imports.keys(), key=lambda x: x.lower()):
        print(f"  {d}")

    print()
    print("Capabilities (heuristic)")
    for c in caps:
        print(f"  {c}")

    print()
    print("Sample imported functions")
    shown = 0
    for d in sorted(imports.keys(), key=lambda x: x.lower()):
        for f in imports[d][:8]:
            print(f"  {d}!{f}")
            shown += 1
            if shown >= 30:
                break
        if shown >= 30:
            break


if __name__ == "__main__":
    main()
