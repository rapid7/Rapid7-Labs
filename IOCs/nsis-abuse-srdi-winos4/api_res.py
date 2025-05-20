import pefile
import os

def mlwr_hash(name: str) -> int:
    h = 0x35
    for c in name:
        h = (3 * h + ord(c)) & 0xFFFFFFFF
    return h

target_hashes = {
    0x030AA4DD,  # LoadLibraryA
    0x03283C47,  # VirtualAlloc
    0xF07B18EE,  # GetCurrentThread
    0xAF757DAE,  # WaitForSingleObject
    0x00FD0820,  # CreateFileA
    0x00FD441A,  # GetFileSize
    0x0009B2EB,  # ReadFile
    0x0103F598,  # MessageBoxA
    0xEF1BFA4A,  # ShellExecuteA
}


dlls_to_check = [
    r"C:\Windows\SysWOW64\kernel32.dll",
    r"C:\Windows\SysWOW64\kernelbase.dll",
    r"C:\Windows\SysWOW64\user32.dll",
    r"C:\Windows\SysWOW64\shell32.dll",
]

def resolve_hashes(target_hashes, dll_paths):
    resolved = {}
    for dll_path in dll_paths:
        if not os.path.exists(dll_path):
            continue
        try:
            pe = pefile.PE(dll_path)
            if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                continue
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode(errors="ignore")
                    h = mlwr_hash(name)
                    if h in target_hashes and h not in resolved:
                        resolved[h] = f"{name} ({os.path.basename(dll_path)})"
                if exp.forwarder:
                    try:
                        fwd = exp.forwarder.decode(errors="ignore")
                        fwd_func = fwd.split('.')[-1].split('#')[0]
                        if fwd_func.isidentifier():
                            h = mlwr_hash(fwd_func)
                            if h in target_hashes and h not in resolved:
                                resolved[h] = f"{fwd_func} (forwarded via {os.path.basename(dll_path)} → {fwd})"
                    except:
                        continue
        except Exception as e:
            print(f"[!] Error reading {dll_path}: {e}")
    return resolved

resolved = resolve_hashes(target_hashes, dlls_to_check)

print("\n=== RESOLVED HASHES ===")
for h in sorted(target_hashes):
    label = resolved.get(h, "<not resolved>")
    print(f"{h:08X} ({h}) → {label}")
