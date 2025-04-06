<p align="center">
  <img src="https://github.com/osnolanarf/reputator/blob/main/reputator_logo.png?raw=true" alt="REPUTATOR logo" width="600"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-blue?style=flat-square" alt="PowerShell">
  <img src="https://img.shields.io/badge/GPL--3.0-License-green?style=flat-square" alt="License: GPL-3.0">
  <img src="https://img.shields.io/badge/Version-2.3-lightgrey?style=flat-square" alt="Version 2.3">
</p>


> 🇪🇸 [Ver este README en español](README.md)

---

<img width="1000" alt="reputatorhash" src="https://github.com/cybevner/reputator/assets/59768231/dd63bc55-0298-4a6c-bb97-a4fe6aadcb5f">

## 🔎 Description

`Reputator` is a PowerShell script designed to check the reputation of file hashes, IP addresses, and domains using [`VirusTotal`](https://www.virustotal.com/) and [`Hybrid Analysis`](https://www.hybrid-analysis.com/). It displays all results in a clean, color-coded table for quick and easy analysis.

The original idea was inspired by [`Malwoverview`](https://github.com/alexandreborges/malwoverview), but this version is streamlined: it focuses on reputation via VirusTotal (and now Hybrid Analysis), works natively with PowerShell (no Python), and does **not** require booting up a REMnux VM to check a few IOCs.

Since version 2, Hybrid Analysis verdicts are also included in the results table.

---

## ⚙️ How It Works

Run `reputator.ps1` with one of the following options:

- `-h` : Analyze a list of file hashes.
- `-i` : Analyze a list of IP addresses.
- `-d` : Analyze a list of domains.
- `-help` : Show help menu.

---

## 📦 Requirements

- A valid [`VirusTotal API key`](https://developers.virustotal.com/reference/getting-started).
- A valid [`Hybrid Analysis API key`](https://www.hybrid-analysis.com/docs/api/v2).
- Text files with the indicators you want to analyze.
- [PSWriteColor](https://www.powershellgallery.com/packages/PSWriteColor): Install it with:

```powershell
Install-Module -Name PSWriteColor -Force
```

---

## ▶️ Usage

Run the script by specifying the type of input and, optionally, the path to the file:

```powershell
reputator.ps1 -h -hashFile "C:\path\to\hashes.txt"
reputator.ps1 -i -ipFile "C:\path\to\ips.txt"
reputator.ps1 -d -domainFile "C:\path\to\domains.txt"
```

### ✅ Example – File Hash Reputation

```
MUESTRA      HASH                                                             VT NOMBRE     VT DETECCIONES    VT PRIMER ANALISIS    VT ULTIMO ANALISIS    HYBRID-ANALYSIS
-------      ----                                                             -----------   ----------------  ---------------------  ---------------------  ----------------
Hash_1       00000075d77e227cdb2d386181e42f42b579eb16403143dc54cd4a3d17fc8622 lhgew.exe     65                2015-05-15 18:42:36     2023-10-01 05:22:31     malicious
Hash_2       0d7b9f1850db74b66b0b89af6ae89368600541f6bbfbbb2f6fed32ec44839699 deoakoy.exe   62                2015-05-30 11:00:25     2023-05-10 19:35:26     malicious
Hash_3       B99D...450                                                      N/A           N/A               N/A                    N/A                    N/A
```

### ✅ Example – IP Reputation

```
MUESTRA    IP             COUNTRY    VT DETECTIONS    VT FIRST ANALYSIS      VT LAST ANALYSIS
-------    --             -------    -------------    ------------------      ------------------
IP_1       45.133.5.148   AU         0                N/A                     N/A
IP_5       35.205.61.67   BE         4                N/A                     2023-08-01 01:19:58
```

### ✅ Example – Domain Reputation

```
MUESTRA    DOMAIN                  VT DETECTIONS    VT CREATION DATE     VT LAST ANALYSIS
-------    -------                 --------------   ------------------    ------------------
Domain_1   finformservice.com      18               2023-06-28            2023-07-27 20:15:13
Domain_5   wexonlake.com           20               2023-05-01            2023-07-27 11:01:18
Domain_7   marca.com               0                1997-03-12            2023-08-01 02:14:13
```

---

## 🖥 Add Script to PATH (optional)

To run `reputator.ps1` from any location in `cmd` or `PowerShell`:

1. Open “Edit environment variables for your account”.
2. Under **System Variables**, select `Path` → Edit → New.
3. Add the full path to the folder containing `reputator.ps1`.
4. Restart your shell or terminal.

Or via command:

```cmd
setx PATH "%PATH%;C:\your\script\directory" /M
```

---

## 📜 Changelog

### v2.3
- Input validation added for hashes, IPs, and domains.
- Colored output: Red for malicious, Green for clean.
- File paths can be passed as arguments.

### v2.2
- Added `VT NOMBRE` (VirusTotal name of the file) column.

### v2.1
- Fixed errors when a hash doesn't exist on VirusTotal.

### v2.0
- Added Hybrid Analysis reputation for hashes.
- Error messages and help menu.
- Color coding for AV detections.

### v1.0
- Initial version: VirusTotal lookups for hashes, IPs, and domains.

---

## 🙌 Credits & Inspiration

- Inspired by [`Malwoverview`](https://github.com/alexandreborges/malwoverview)
- Made for SOC analysts, blue teamers, and DFIR practitioners.

---

## ⭐ Contribute & Support

If this tool helped you, give it a ⭐ star!  
Pull requests and feature suggestions (like Triage/Any.Run integration) are welcome.
