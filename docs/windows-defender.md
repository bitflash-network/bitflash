# Windows Defender and Bitflash binaries

Microsoft Defender sometimes quarantines Bitflash builds on Windows. This page
records what it flags and why, how to report a false positive to Microsoft
(with the text ready to paste), and what actually lowers the chance of a
detection.

## What gets flagged

| File | Detection | Kind | Status |
|---|---|---|---|
| `bitflash.exe` (wallet), local dev builds | `Trojan:Win32/Bearfoos.A!ml` | cloud machine-learning verdict on one file hash, later pushed to other copies as a *FastPath* signature | release 1.2.31 **not** flagged (scanned 2026-10-30, signatures 1.463.33.0) |
| `xmrig/xmrig.exe` (Bitflash Miner) | `Trojan:Win64/HashvaultMiner.A` | named signature for XMRig itself | flagged in every release; the official, unchanged XMRig 6.26.0 binary |
| `xmrig/WinRing0x64.sys` (Miner up to 1.2.31) | `VulnerableDriver:WinNT/Winring0` | known-vulnerable kernel driver | flagged on download; **removed from the package after 1.2.31** (see below) |
| `xmrig` on Linux / macOS | `Trojan:Linux/CoinMiner!rfn`, `Misleading:MacOS/CoinMiner.BC!MTB` | named signatures | only matters when the archive is opened on a Windows machine |

The suffix tells you what kind of detection it is:

- **`!ml`** -- a machine-learning model in Microsoft's cloud judged a file it
  had never seen before. The verdict is tied to that file's SHA-256. A new
  build is a new hash with no history, so one build can be flagged and the
  next one not. These are the ones a false-positive report fixes.
- **A family name without `!ml`** (`HashvaultMiner.A`) -- a signature written
  for that program. Microsoft classifies XMRig as a miner on purpose, because
  cryptojacking malware drops the same binary. Reports on it are normally
  declined; plan around it rather than expecting it to go away.
- **`VulnerableDriver`** -- the driver is on Microsoft's vulnerable-driver
  blocklist. That is a policy decision, not a mistake, and it will not be
  reversed.

How the 2026-10-30 detection played out, from the Defender log (event 1116):
the first copy (`uitest\bitflash.exe`) was caught by real-time protection with
detection type *Concrete*, the cloud verdict; two minutes later a second copy
of the same build elsewhere on disk was caught as *FastPath*, a signature the
cloud sent down for that hash. The published 1.2.31 wallet, downloaded and
unpacked on the same machine the same day, was not flagged.

## Reporting a false positive to Microsoft

Do this for every `!ml` detection of a Bitflash binary, ideally for each
release's `Bitflash.exe` and `BtfChat.exe` as soon as it is published -- a
file Microsoft has analysed and cleared is not judged by the model again.

1. Open <https://www.microsoft.com/en-us/wdsi/filesubmission>.
2. Choose **Software developer**. It asks you to sign in with a Microsoft
   account; developer submissions are prioritised and you get a submission
   ID to track. (Home customer works without an account, but slower.)
3. Product: **Microsoft Defender Antivirus (Windows 10/11)** -- the
   consumer Defender built into Windows.
4. Upload the file. Use the exact file from the release zip, not a local
   build: the verdict is per hash, and the release is the hash users have.
   Files up to 500 MB are accepted; a zip of the single exe is fine.
5. "What do you believe this file is?" -> **Incorrectly detected as
   malware/malicious**.
6. Detection name: copy it exactly, e.g. `Trojan:Win32/Bearfoos.A!ml`.
7. Additional information: paste the text below, then submit.

The answer comes by email and on the submission page, usually within a few
days. When it says the detection was removed, the definitions catch up on
their own; to see the change on a machine right away (run as administrator
by whoever owns that machine -- it touches only Defender's downloaded
definitions):

```
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -removedefinitions -dynamicsignatures
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate
```

Then restore the file from *Windows Security -> Protection history*.

### Text for the wallet (`Bitflash.exe`, `BtfChat.exe`)

Replace VERSION and the hash (it is in `SHA256SUMS` in the release).

```
File: Bitflash.exe from Bitflash-VERSION-windows-with-tor.zip
SHA-256: <hash from SHA256SUMS>
Detection: Trojan:Win32/Bearfoos.A!ml

This is a false positive. Bitflash is an open source (MIT) cryptocurrency
wallet and full node: a desktop GUI built with Dear ImGui and GLFW, using
RandomX for proof of work and Tor for networking. It installs nothing, does
not persist, and only runs when the user starts it.

Source code: https://github.com/bitflash-network/bitflash
Release: https://github.com/bitflash-network/bitflash/releases/tag/vVERSION
The binary is built by GitHub Actions from the tagged commit
(.github/workflows/release.yml); the build is reproducible
(docs/release-verification.md) and SHA256SUMS is signed with the project's
release key, fingerprint 910A 2B4C CA87 9E81 FB4B 2AEA 1D4A 53D3 B78A A4B8.

Mining is opt-in and visible: a fresh install does not mine; it starts
only after the user picks a mining mode in the window, shows its hashrate
there, and pays the user's own wallet. The node can also serve a local
stratum endpoint to the user's own miners (pool and P2Pool modes), which is
why it contains stratum and XMRig strings. Please remove the detection.
```

### Text for the miner (`xmrig.exe`)

Expect this one to be declined: it is the stock XMRig binary and Microsoft
detects XMRig deliberately. Submitting it still records that this package is
a known, legitimate distribution. Send it only after a release, with the
release's hash.

```
File: xmrig/xmrig.exe from Bitflash-Miner-VERSION-windows.zip
SHA-256: <hash from the SHA256SUMS inside the zip>
Detection: Trojan:Win64/HashvaultMiner.A

This is the official, unmodified XMRig 6.26.0 release binary
(https://github.com/xmrig/xmrig/releases/tag/v6.26.0, same SHA-256 as
published there), shipped inside "Bitflash Miner", an open source launcher
for mining the Bitflash cryptocurrency: https://github.com/bitflash-network/bitflash
(scripts/bitflash-miner). The user downloads it on purpose, runs mine.cmd
by hand with their own payout address, and sees the miner's console the
whole time. Nothing is installed, hidden, persisted or started
automatically. We ask that this distribution not be classified as a
trojan; a PUA/"miner" classification the user can allow would be accurate.
```

Do not submit `WinRing0x64.sys`: it is genuinely vulnerable, and it is no
longer shipped.

## What reduces detections, and what does not

Measured or documented, in order of what it is worth:

1. **Report each release's binaries** (above). The only thing that reverses
   an `!ml` verdict on a hash already out there, and it costs nothing.

2. **Ship one hash per release, built in CI.** The verdict follows the hash.
   Every local build is a brand-new file the cloud has never seen, which is
   exactly what the model is most suspicious of; the 2026-10-30 detections
   were local builds of a work-in-progress branch. Users get the CI build,
   whose hash gets reputation as people download it without incident. Do not
   ask testers to run ad-hoc builds on Windows when a CI artifact will do.

3. **Version information in the PE (done).** `src/bitflash.rc` now carries a
   `VERSIONINFO` block: product name, description, version, copyright,
   original filename, link to the source. Before, the wallet had none -- no
   name, no version, no publisher, unsigned -- the profile of a dropper. This
   is one of the features the classifier reads and costs nothing; it is also
   a precondition for free signing through SignPath (below), which requires
   product name and version metadata in every signed binary. On its own it
   does not guarantee anything.

4. **Drop `WinRing0x64.sys` from the Miner (done).** XMRig only loads it
   when started as administrator, to tweak CPU registers (MSR) for a few
   percent more RandomX hashrate; `mine.cmd` never runs as administrator, so
   nobody was using it. Windows' vulnerable-driver blocklist refuses to load
   it anyway on current Windows 11, and its presence made Defender report the
   whole zip on download. Without it XMRig prints one line saying MSR could
   not be set and mines normally.

5. **Code signing (Authenticode).** Signed files are trusted more by the
   model and by SmartScreen; a signature is not immunity -- signed malware
   exists and gets flagged. The constraint here is not the money but the
   name: an Authenticode certificate shows the publisher's verified legal
   name to everyone who opens the file's properties, and the founder does
   not publish a name.
   - **SignPath Foundation** -- free for open source projects; the
     certificate is issued to *SignPath Foundation*, which appears as the
     publisher, so no personal name is exposed. Conditions: OSI licence (MIT
     is fine), binaries built in CI from the project's own source (it signs
     `Bitflash.exe`/`BtfChat.exe`, never the third-party `xmrig.exe` or
     `tor.exe`), a published code-signing policy page, MFA for the team,
     manual approval of each release, product name/version metadata (now
     present), and no malware/PUA. Acceptance is at their discretion and a
     wallet with built-in mining may get questions; apply at
     <https://signpath.org> with the wallet only. **This is the recommended
     route.**
   - **Azure Artifact Signing** (formerly Trusted Signing, about US$10 a
     month) -- issues certificates to individuals only in the USA and Canada,
     and to organisations with a verifiable registration; the certificate
     carries that legal name. Not available as things stand.
   - **Commercial OV certificate** (roughly US$200-400 a year, private key on
     a hardware token or cloud HSM since 2023) -- same problem: the legal
     name of a person or company is in the certificate. EV certificates no
     longer buy instant SmartScreen reputation either.

6. **Miner strings in the wallet.** The wallet mines with its own RandomX
   code, not XMRig, but it is also a pool: it serves stratum to XMRig
   (`mining.subscribe`, `login`, the `XMRig/6.26.0` agent in the P2Pool
   stratum, XMRig named in help and log text). 1.2.31 carries all of that and
   scans clean, so these strings are not what the named miner signatures
   match, and they are not what tipped the `!ml` verdict on one dev build and
   not on the release. Removing them would break the pool modes for nothing;
   renaming or obfuscating strings to dodge detection is the wrong direction
   -- obfuscation is itself a malware feature models look for. What matters
   is behaviour, and that is already right: a fresh install does not mine,
   mining starts only from a mode the user picks, the window shows it, and
   nothing persists or starts with Windows. Keep it that way.

What does not help: packing or compressing the exe (UPX and the like raise
detections), changing file names, or telling users to disable Defender. The
Miner's README tells users how to restore `xmrig.exe` and add an exclusion
for that folder themselves; that is their decision on their machine, and
it remains the only fix for the XMRig signature.
