# PokeXGames — HWID Collection & Fingerprinting

PokeXGames is a heavily customized PokeTibia (an OTClient-based Pokémon MMO). Its client, `pxgme.exe` (x86-64 Windows PE, ~20 MB, MSVC C++ with SDL2/OpenGL), silently collects hardware metrics from the host machine and derives a Hardware Identifier (HWID) used for device locking / license binding. There is no prompt, no setting, and no mention of it in-game — the collection happens in the background via Windows APIs and the registry.

This document describes the full pipeline: what is collected, how it is hashed, and what it takes to change or forge an HWID. Verified on the June 2026 build.

## 1. The Formula

```
HWID = SHA1_raw( hex(SHA1( CPU ‖ OS ‖ UserName ‖ RAM ‖ VolSerial ‖ CompName ‖ MachineGuid )) ‖ SALT )
```

- First pass: SHA-1 of the serialized metrics → **40-char lowercase hex string**
- Append the 16-byte static salt → 56-byte string
- Second pass: SHA-1 of that → final **20-byte raw digest**
- Salt (hardcoded, unchanged across builds):

```
M24i1HcW18(&Nlve
```

Hashing is OpenSSL CRYPTOGAMS SHA-1 (assembly, x86_64). SHA-256/SHA-512 are linked in the binary but **not used** for HWID.

## 2. The Seven Metrics

Collected in this exact order — order matters:

| # | Metric | Source |
|---|--------|--------|
| 1 | CPU name | Registry `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` → `ProcessorNameString` |
| 2 | OS version | `GetVersionExA` + `GetNativeSystemInfo` → e.g. `"Windows 10, 64-bit"` incl. edition and build |
| 3 | Windows username | `GetUserNameW`, converted to UTF-8 |
| 4 | Total physical RAM | `GlobalMemoryStatusEx` → `ullTotalPhys` as decimal integer |
| 5 | C: volume serial | `GetVolumeInformationA("c:\\")`, then `(serial >> 16) + serial` (hiword + loword) |
| 6 | Computer name | `GetComputerNameA`, falls back to `GetUserNameA` if empty |
| 7 | MachineGuid | Registry `HKLM\SOFTWARE\Microsoft\Cryptography` → `MachineGuid` |

Strings are appended to a `std::stringstream`-like buffer via `operator<<`; numbers (RAM, volume serial) are formatted as decimal and appended the same way. No separators — pure concatenation.

A MAC-address collector (`GetAdaptersInfo`) exists in the binary but is **not** part of the main HWID chain; it is referenced via function-pointer tables, presumably for secondary checks.

## 3. Hash Engine Details

One dual-mode function does both passes (MSVC x64 calling convention):

| Parm | Register | Meaning |
|------|----------|---------|
| output `std::string*` | RCX | result written here |
| context | RDX | passed through, unused |
| input `std::string*` | R8 | data to hash (`+0x00` = char* data, `+0x08` = length) |
| mode | R9 | `0` = 40-char hex output, `1` = raw 20-byte digest |

- Pass 1 (aggregator): mode `0` → hex string of the serialized buffer
- Pass 2 (salt appender): appends the salt to that hex string, mode `1` → raw 20-byte HWID

**Verification path:** in the license-comparison path, the 40-char hex is truncated to 32 chars (first 128 bits) and parsed into a 16-byte GUID.

## 4. Reproducing / Inspecting with Frida

Hook the hash engine (`base + 0x41b7f0` on the June 2026 build — rebase per patch):

```javascript
const sha1 = Module.findBaseAddress("pxgme.exe").add(0x41b7f0);
Interceptor.attach(sha1, {
  onEnter(args) {
    const input = args[2];                     // std::string*
    const data = input.readPointer();
    const len = input.add(8).readU64();
    const mode = args[3].toInt32();
    if (len > 0 && len < 4096 && !data.isNull()) {
      console.log(mode === 0 ? "[SHA1 HEX in]" : "[SHA1 RAW in]",
                  data.readUtf8String(len));
    }
  }
});
```

To watch the 7 metrics being concatenated, hook the string `operator<<` (`base + 0xe4fc80` on the same build): it fires 7 times, `RDX` = data, `R8` = length. Numeric inserts use `0xc9c400` (RAM, 64-bit) and `0xc9bfc0` (volume serial, 16-bit).

## 5. Security Properties

- **Deterministic per machine**, resistant to casual tampering — reproducing it requires all 7 metrics, the exact order, the hex-encode step, and the salt.
- **But everything is spoofable with admin rights**: volume serial, computer name, username, and MachineGuid can all be changed; RAM and CPU strings can be intercepted at the API/registry layer.
- **SHA-1 is cryptographically weak** (SHAttered, 2017). For a device-binding token this is a modest weakness — the real exposure is that the construction is fully known and static across builds.
- The double-hash construction adds no real protection once the salt is known; it only obscures the raw metrics in transit.

## 6. What Changes Your HWID

SHA-1 has the avalanche property: **flip one bit in any metric and the final HWID is a completely different 20 bytes.** There is no similarity between the old and new token — the server cannot tell "same PC, one change" from "different PC" by looking at the HWID alone.

And the metrics change more often than people think:

| Metric | Changes when you... |
|--------|---------------------|
| CPU name | replace the CPU |
| OS version + build | install a Windows feature update (build number bumps) |
| Username | rename/create the Windows user |
| Total RAM | add/remove a RAM stick |
| C: volume serial | format or replace the C: drive (or change it with a 1-line tool) |
| Computer name | rename the PC |
| MachineGuid | reinstall Windows |

Practical consequences:

- **Fragile for legit players**: a routine Windows feature update or a RAM upgrade produces a brand-new HWID. If the game uses it for device locking, ordinary maintenance looks like a new device.
- **Trivial to rotate deliberately**: changing the volume serial or computer name — a 30-second, fully reversible operation — gives you a fresh HWID. As an anti-ban mechanism it only stops people who don't know this.
- **No fuzzy matching server-side**: because of the avalanche effect, the server can only track "HWID changed again", never *which* metric changed.

## 7. Anti-Debug? No.

The binary imports APIs that *look* like anti-debugging, but dynamic analysis (x64dbg) shows none of them are used that way:

- **`IsDebuggerPresent` + `DebugBreak`** — 6 call sites, all guarded by global debug flags (developer helpers) or the standard MSVC thread-naming exception (`0x406D1388`). Never fires in normal use.
- **`QueryPerformanceCounter` / `GetTickCount` / `RDTSC`** — SDL and engine timers. No delta-trap logic.
- **No PEB checks** (`BeingDebugged` hardware breakpoint never triggered), no `NtQueryInformationProcess` / `NtSetInformationThread` from game code, no `.text` CRC/checksum loops, no `INT3` scans, no IAT hook detection.
- The "integrity check file" created at startup is a **singleton lock** (one client instance at a time), not a code-integrity check.

Bottom line: nothing in the client stops you from attaching a debugger or Frida. Any real enforcement would be server-side, not in `pxgme.exe`.

## Appendix — Addresses (June 2026 build, base `0x140000000`)

Shift on every recompile; algorithm and constants are stable.

| Role | Address |
|------|---------|
| HWID aggregator (collect + 1st hash) | `0x14041bf90` |
| Salt appender + 2nd hash | `0x14041c7e0` |
| SHA-1 engine (dual-mode) | `0x14041b7f0` |
| Collectors (CPU, OS, user, RAM, volserial, compname, guid) | `0x1403e7540`, `0x1403e7ad0`, `0x1403e7740`, `0x1403e7930`, `0x1403eaca0`, `0x1403ead00`, `0x1403eae60` |
| Salt string | `0x140f835e8` |
| String `operator<<` | `0x140e4fc80` |
| Numeric `operator<<` (u64 / u16) | `0x140c9c400` / `0x140c9bfc0` |
