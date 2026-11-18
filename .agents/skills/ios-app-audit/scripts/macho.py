"""Minimal Mach-O reader for iOS app binaries (standard library only).

Reads what an iOS static review needs without otool, codesign or jtool:
  - fat/thin headers, slice selection (arm64e > arm64 > first), header flags (PIE, stack/heap exec)
  - load commands: segments and sections, linked dylibs (weak, re-export), rpaths, encryption info
    (cryptid), build version / minimum OS, code signature location
  - symbols: undefined imports (symtab and chained fixups), local and debug (stab) symbol counts
  - code signature: CodeDirectory identifier, team ID, flags, embedded XML entitlements
  - section strings: __cstring, __objc_classname, __objc_methname, __swift5_reflstr, __ustring

The file is untrusted. Every offset is bounds-checked; a malformed binary yields partial results
and an "errors" list instead of an exception.
"""
from __future__ import annotations

import plistlib
import re
import struct

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM = 0x0000000C
CPU_SUBTYPE_ARM64E = 2

MH_FLAGS = {
    0x00200000: "PIE",
    0x00020000: "ALLOW_STACK_EXECUTION",
    0x01000000: "NO_HEAP_EXECUTION",
    0x00800000: "HAS_TLV_DESCRIPTORS",
    0x02000000: "APP_EXTENSION_SAFE",
}
FILETYPES = {1: "object", 2: "execute", 6: "dylib", 8: "bundle", 9: "dylib_stub", 0xB: "kext"}

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_LAZY_LOAD_DYLIB = 0x20
LC_VERSION_MIN_IPHONEOS = 0x25
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_REQ_DYLD = 0x80000000
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CS_FLAGS = {0x1: "VALID", 0x2: "ADHOC", 0x4: "GET_TASK_ALLOW", 0x200: "RESTRICT", 0x800: "LIBRARY_VALIDATION",
            0x10000: "RUNTIME", 0x2000: "ENFORCEMENT"}
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 7: "iOSSimulator", 11: "visionOS"}

STRING_SECTIONS = {
    ("__TEXT", "__cstring"): "cstring",
    ("__TEXT", "__objc_classname"): "objc_classname",
    ("__TEXT", "__objc_methname"): "objc_methname",
    ("__TEXT", "__swift5_reflstr"): "swift_reflstr",
    ("__TEXT", "__oslogstring"): "oslogstring",
    ("__RODATA", "__cstring"): "cstring",
}


def _ver(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def _cstr(buf: bytes, off: int, limit: int = 4096) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off, min(len(buf), off + limit))
    if end < 0:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("utf-8", "replace")


class MachO:
    def __init__(self, path: str):
        self.path = path
        self.errors: list[str] = []
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.slices: list[dict] = []
        self.base = 0
        self.size = len(self.data)
        self.info: dict = {}
        self.sections: list[dict] = []
        self.dylibs: list[dict] = []
        self.imports: set[str] = set()
        self.exports_count = 0
        self.local_symbols = 0
        self.stab_symbols = 0
        self.entitlements: dict | None = None
        self.entitlements_raw: str = ""
        self.codesign: dict = {}
        try:
            self._pick_slice()
            self._parse()
        except (struct.error, ValueError, IndexError) as e:
            self.errors.append(f"parse error: {e}")

    # ------------------------------------------------------------ headers
    def _pick_slice(self) -> None:
        if len(self.data) < 8:
            raise ValueError("file too small")
        magic_be = struct.unpack(">I", self.data[:4])[0]
        if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
            n = struct.unpack(">I", self.data[4:8])[0]
            if n > 32:
                raise ValueError("implausible fat arch count")
            off = 8
            for _ in range(n):
                if magic_be == FAT_MAGIC:
                    cputype, sub, o, sz, _a = struct.unpack(">iiIII", self.data[off:off + 20])
                    off += 20
                else:
                    cputype, sub, o, sz, _a, _r = struct.unpack(">iiQQII", self.data[off:off + 32])
                    off += 32
                self.slices.append({"cputype": cputype & 0xFFFFFFFF, "cpusubtype": sub & 0xFFFFFF, "offset": o, "size": sz})
            pick = None
            for want in ((CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E), (CPU_TYPE_ARM64, None)):
                for s in self.slices:
                    if s["cputype"] == want[0] and (want[1] is None or s["cpusubtype"] == want[1]):
                        pick = pick or s
            pick = pick or (self.slices[0] if self.slices else None)
            if not pick or pick["offset"] + pick["size"] > len(self.data):
                raise ValueError("fat slice out of range")
            self.base, self.size = pick["offset"], pick["size"]
        else:
            self.slices.append({"cputype": None, "offset": 0, "size": len(self.data)})

    def _u32(self, off: int) -> int:
        return struct.unpack("<I", self.data[self.base + off:self.base + off + 4])[0]

    def _parse(self) -> None:
        d, b = self.data, self.base
        magic = struct.unpack("<I", d[b:b + 4])[0]
        if magic not in (MH_MAGIC_64, MH_MAGIC):
            raise ValueError(f"not a little-endian Mach-O (magic {magic:#x})")
        is64 = magic == MH_MAGIC_64
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack("<iiIIII", d[b + 4:b + 28])
        hdr = 32 if is64 else 28
        self.info = {
            "arch": {CPU_TYPE_ARM64: "arm64", CPU_TYPE_ARM: "armv7"}.get(cputype & 0xFFFFFFFF, hex(cputype & 0xFFFFFFFF)),
            "arm64e": (cputype & 0xFFFFFFFF) == CPU_TYPE_ARM64 and (cpusub & 0xFF) == CPU_SUBTYPE_ARM64E,
            "filetype": FILETYPES.get(filetype, filetype),
            "flags": [n for bit, n in MH_FLAGS.items() if flags & bit],
            "pie": bool(flags & 0x00200000),
            "slices": [{k: v for k, v in s.items() if k != "size"} for s in self.slices],
            "encryption": None,
            "min_os": None, "sdk": None, "platform": None,
            "rpaths": [],
            "has_restrict_segment": False,
        }
        off = b + hdr
        end = off + sizeofcmds
        if ncmds > 4096 or end > b + self.size:
            raise ValueError("load commands out of range")
        symtab = None
        chained = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", d[off:off + 8])
            if cmdsize < 8 or off + cmdsize > end:
                self.errors.append("truncated load command")
                break
            body = d[off:off + cmdsize]
            if cmd in (LC_SEGMENT_64, LC_SEGMENT):
                self._segment(body, cmd == LC_SEGMENT_64)
            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB):
                name_off = struct.unpack("<I", body[8:12])[0]
                cur, compat = struct.unpack("<II", body[16:24])
                kind = {LC_LOAD_WEAK_DYLIB: "weak", LC_REEXPORT_DYLIB: "reexport", LC_LAZY_LOAD_DYLIB: "lazy"}.get(cmd, "load")
                self.dylibs.append({"name": _cstr(body, name_off), "kind": kind, "current_version": _ver(cur)})
            elif cmd == LC_RPATH:
                self.info["rpaths"].append(_cstr(body, struct.unpack("<I", body[8:12])[0]))
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                cryptoff, cryptsize, cryptid = struct.unpack("<III", body[8:20])
                self.info["encryption"] = {"cryptoff": cryptoff, "cryptsize": cryptsize, "cryptid": cryptid}
            elif cmd == LC_BUILD_VERSION:
                platform, minos, sdk = struct.unpack("<III", body[8:20])
                self.info.update(platform=PLATFORMS.get(platform, platform), min_os=_ver(minos), sdk=_ver(sdk))
            elif cmd == LC_VERSION_MIN_IPHONEOS:
                ver, sdk = struct.unpack("<II", body[8:16])
                self.info.update(platform="iOS", min_os=_ver(ver), sdk=_ver(sdk))
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack("<IIII", body[8:24])
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                chained = struct.unpack("<II", body[8:16])
            elif cmd == LC_CODE_SIGNATURE:
                dataoff, datasize = struct.unpack("<II", body[8:16])
                self._codesign(dataoff, datasize)
            off += cmdsize
        if symtab:
            self._symbols(*symtab, is64=is64)
        if chained:
            self._chained_imports(*chained)

    def _segment(self, body: bytes, is64: bool) -> None:
        segname = body[8:24].split(b"\x00")[0].decode("ascii", "replace")
        if segname == "__RESTRICT":
            self.info["has_restrict_segment"] = True
        if is64:
            nsects = struct.unpack("<I", body[64:68])[0]
            p, step = 72, 80
        else:
            nsects = struct.unpack("<I", body[48:52])[0]
            p, step = 56, 68
        for _ in range(min(nsects, 512)):
            s = body[p:p + step]
            if len(s) < step:
                break
            sect = s[0:16].split(b"\x00")[0].decode("ascii", "replace")
            seg = s[16:32].split(b"\x00")[0].decode("ascii", "replace")
            if is64:
                addr, size = struct.unpack("<QQ", s[32:48])
                offset = struct.unpack("<I", s[48:52])[0]
            else:
                addr, size, offset = struct.unpack("<III", s[32:44])
            self.sections.append({"segment": seg, "section": sect, "offset": offset, "size": size, "addr": addr})
            p += step

    # ------------------------------------------------------------ symbols
    def _symbols(self, symoff: int, nsyms: int, stroff: int, strsize: int, is64: bool) -> None:
        d, b = self.data, self.base
        if nsyms > 5_000_000 or b + stroff + strsize > len(d):
            self.errors.append("symbol table out of range")
            return
        strtab = d[b + stroff:b + stroff + strsize]
        size = 16 if is64 else 12
        for i in range(nsyms):
            o = b + symoff + i * size
            if o + size > len(d):
                break
            n_strx, n_type, n_sect = struct.unpack("<IBB", d[o:o + 6])
            if n_type & 0xE0:  # N_STAB debug entries
                self.stab_symbols += 1
                continue
            ntype = n_type & 0x0E
            ext = n_type & 0x01
            if ntype == 0x0 and ext:  # N_UNDF external -> import
                name = _cstr(strtab, n_strx, 512)
                if name:
                    self.imports.add(name)
            elif ntype == 0xE:  # N_SECT
                if ext:
                    self.exports_count += 1
                else:
                    self.local_symbols += 1

    def _chained_imports(self, dataoff: int, datasize: int) -> None:
        d, b = self.data, self.base
        blob = d[b + dataoff:b + dataoff + datasize]
        if len(blob) < 28:
            return
        _ver_, _starts, imports_off, symbols_off, count, imp_fmt, _sym_fmt = struct.unpack("<IIIIIII", blob[:28])
        if count > 1_000_000:
            return
        width = {1: 4, 2: 8, 3: 16}.get(imp_fmt)
        if not width:
            return
        for i in range(count):
            o = imports_off + i * width
            if o + width > len(blob):
                break
            if imp_fmt == 3:
                raw = struct.unpack("<Q", blob[o:o + 8])[0]
                name_off = raw >> 32
            else:
                raw = struct.unpack("<I", blob[o:o + 4])[0]
                name_off = raw >> 9
            name = _cstr(blob, symbols_off + name_off, 512)
            if name:
                self.imports.add(name)

    # ------------------------------------------------------------ code signature
    def _codesign(self, dataoff: int, datasize: int) -> None:
        d, b = self.data, self.base
        blob = d[b + dataoff:b + dataoff + datasize]
        if len(blob) < 12:
            return
        magic, length, count = struct.unpack(">III", blob[:12])
        if magic != CSMAGIC_EMBEDDED_SIGNATURE or count > 64:
            self.errors.append("no embedded signature superblob")
            return
        self.codesign["present"] = True
        for i in range(count):
            typ, off = struct.unpack(">II", blob[12 + i * 8:20 + i * 8])
            if off + 8 > len(blob):
                continue
            bmagic, blen = struct.unpack(">II", blob[off:off + 8])
            body = blob[off:off + blen]
            if bmagic == CSMAGIC_CODEDIRECTORY and "identifier" not in self.codesign:
                self._code_directory(body)
            elif bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                raw = body[8:]
                self.entitlements_raw = raw.decode("utf-8", "replace")
                try:
                    self.entitlements = plistlib.loads(raw)
                except Exception:  # noqa: BLE001
                    self.errors.append("entitlements plist did not parse")
            elif bmagic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
                self.codesign["der_entitlements"] = True
            elif bmagic == CSMAGIC_BLOBWRAPPER:
                self.codesign["cms_signature_bytes"] = max(0, blen - 8)

    def _code_directory(self, cd: bytes) -> None:
        if len(cd) < 44:
            return
        version, flags, _hash_off, ident_off = struct.unpack(">IIII", cd[8:24])
        hash_size, hash_type = cd[36], cd[37]
        self.codesign.update(
            cd_version=hex(version),
            flags=[n for bit, n in CS_FLAGS.items() if flags & bit],
            identifier=_cstr(cd, ident_off, 256),
            hash_type={1: "sha1", 2: "sha256", 3: "sha256-truncated", 4: "sha384"}.get(hash_type, hash_type),
            hash_size=hash_size,
        )
        if version >= 0x20200 and len(cd) >= 52:
            team_off = struct.unpack(">I", cd[48:52])[0]
            if team_off:
                self.codesign["team_id"] = _cstr(cd, team_off, 64)

    # ------------------------------------------------------------ strings
    def section_strings(self) -> dict[str, list[str]]:
        """Null-terminated strings per string section, from the selected slice."""
        out: dict[str, list[str]] = {}
        for s in self.sections:
            key = STRING_SECTIONS.get((s["segment"], s["section"]))
            if not key or not s["size"]:
                continue
            start = self.base + s["offset"]
            raw = self.data[start:start + min(s["size"], 64 * 1024 * 1024)]
            vals = [x.decode("utf-8", "replace") for x in raw.split(b"\x00") if len(x) >= 2]
            out.setdefault(key, []).extend(vals)
        for s in self.sections:
            if (s["segment"], s["section"]) == ("__TEXT", "__ustring") and s["size"]:
                raw = self.data[self.base + s["offset"]:self.base + s["offset"] + s["size"]]
                out.setdefault("ustring", []).extend(
                    x for x in raw.decode("utf-16-le", "replace").split("\x00") if len(x) >= 3)
        return out

    def all_printable(self, min_len: int = 6) -> list[str]:
        """Printable ASCII runs across the whole slice (fallback when sections are encrypted)."""
        raw = self.data[self.base:self.base + self.size]
        return [m.group(0).decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, raw)]

    def summary(self) -> dict:
        enc = self.info.get("encryption") or {}
        sects = {(s["segment"], s["section"]) for s in self.sections}
        imports = self.imports
        return {
            **self.info,
            "encrypted": bool(enc.get("cryptid")),
            "dylibs": self.dylibs,
            "imports_count": len(imports),
            "local_symbols": self.local_symbols,
            "debug_stab_symbols": self.stab_symbols,
            "stripped": self.local_symbols < 50 and self.stab_symbols == 0,
            "stack_canary": bool(imports & {"___stack_chk_guard", "___stack_chk_fail"}),
            "arc": bool(imports & {"_objc_release", "_objc_retain", "_objc_storeStrong", "_swift_release", "_swift_retain"}),
            "swift": any("libswift" in x["name"] for x in self.dylibs) or any(sec.startswith("__swift5") for _, sec in sects),
            "objc": any(sec.startswith("__objc_") for _, sec in sects),
            "codesign": self.codesign,
            "has_entitlements": self.entitlements is not None,
            "errors": self.errors,
        }
