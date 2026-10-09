# Luna Guard — Project Spec (handoff for GitHub Copilot / VS Code)

> วางไฟล์นี้ที่ `.github/copilot-instructions.md` หรือแนบใน Copilot Chat เป็นบริบทของโปรเจกต์
> UI รองรับภาษาไทย อังกฤษ และจีนตัวย่อ โดยเพิ่มคำแปลใน `locales.json`; ส่วนโค้ด/ชื่อตัวแปรเป็นอังกฤษ

## 1. เป้าหมาย
แอปเดสก์ท็อปบน **Windows** ตรวจจับและกำจัด **XWorm RAT** และมัลแวร์ที่แพร่ผ่านกลโกงแอบอ้าง "MrBeast" (เว็บแจกเงินปลอม, Discord/CAPTCHA ปลอม, infostealer)
เป็น **เครื่องมือเสริม** ไม่ใช่ตัวแทน Defender/Malwarebytes — ใช้ข้อมูลภัยคุกคามสาธารณะของ abuse.ch ที่อัปเดตรายวัน

หลักการออกแบบ (ห้ามละเมิด):
1. **ไม่ลบไฟล์ทิ้งทันที** — ย้ายเข้า quarantine เสมอ และกู้คืนได้
2. `--clean` / "สแกน+กำจัด" แตะเฉพาะ **HIGH**; **MEDIUM/LOW = แจ้งเตือนแล้วให้ผู้ใช้เลือก** (กักกัน / ปลอดภัย)
3. allowlist ใช้กับไฟล์ที่ผู้ใช้ยืนยัน แต่ **แฮชที่ตรงฐานข้อมูลมัลแวร์ชนะ allowlist เสมอ**
4. `remove_finding` / `allow_file` ทำได้เฉพาะ path ที่อยู่ใน **ผลสแกนล่าสุด** (กันถูกใช้ลบไฟล์มั่ว)
5. ใช้เฉพาะ Python standard library ในตัวแกนหลัก; แอปเดสก์ท็อปต้องใช้ `pywebview`, ส่วน `yara-python` เป็น optional
6. เซิร์ฟเวอร์ผูก `127.0.0.1` เท่านั้น และตรวจ token + Host ทุก request

## 2. โครงสร้างไฟล์
| ไฟล์ | หน้าที่ |
|---|---|
| `luna_guard.py` | แกนหลัก: ฐานข้อมูล, อัปเดตฟีด, วิเคราะห์ไฟล์, สแกน 5 ขั้น, กักกัน/กู้คืน, CLI |
| `luna_dashboard.py` | HTTP server ภายในเครื่อง + REST API + job runner + self-test; เปิด browser จากโหมด standalone เฉพาะเมื่อระบุ `--open-browser` |
| `dashboard.html` | UI ไฟล์เดียว (HTML/CSS/JS ล้วน ไม่มี CDN) เรียก API ด้วย polling |
| `locales.json` | ข้อความ UI และคู่มือภาษาไทย อังกฤษ และจีนตัวย่อ (รวมใน EXE) |
| `luna_app.py` | แอปเดสก์ท็อป: เปิด server ในเครื่องแล้วแสดง UI ในหน้าต่าง **pywebview**; ถ้าไม่มี dependency แจ้ง error และไม่เปิด browser |
| `luna_rules.yar` | กฎ YARA (severity: high/medium/low ใน `meta`) |
| `build.bat` | PyInstaller → `dist\LunaGuard.exe` (`--uac-admin`, bundle html+locales+yar) |
| `test_luna.py` | unittest (mock คำสั่ง Windows) |
| `luna_gui.py` | **เลิกใช้** (tkinter รุ่นแรก) ลบได้ |

ข้อมูลผู้ใช้อยู่ที่ `%LOCALAPPDATA%\LunaGuard\`: `threats.db` (SQLite), `quarantine\*.quar` + `index.json`, `config.json` (คีย์ abuse.ch), `history.json` (30 สแกนล่าสุด), `rules\*.yar` (กฎที่ผู้ใช้เพิ่มเอง)

## 3. ฐานข้อมูล (SQLite `threats.db`)
- `hashes(sha256 PK, family, source)` — จาก MalwareBazaar, SHA-256 ที่ ThreatFox ผูกกับ IOC / `add-hash`
- `iocs(value PK, kind ['ip'|'domain'], family, source)` — ThreatFox IOCs ล่าสุด 7 วัน, URLhaus host feed, seed (`beastxm.com`, `beast-days.com`)
- `meta(k PK, v)` — `last_update`
- `allow(sha256 PK, path)` — ไฟล์ที่ผู้ใช้ยืนยันปลอดภัย

## 4. อัปเดตฟีด (`cmd_update`, ต้องมี Auth-Key จาก https://auth.abuse.ch)
คีย์: env `ABUSECH_KEY` ก่อน ถ้าไม่มีอ่าน `config.json` (`get_key`/`save_key`) ส่งเป็น header `Auth-Key`
- **MalwareBazaar** `POST https://mb-api.abuse.ch/api/v1/` — `get_taginfo` (tag, tag.lower()) และ `get_siginfo` (signature), `limit=1000`, TAGS = `XWorm`, `MrBeast` → ตาราง `hashes` (พิมพ์สถานะ `query_status` ทุกครั้ง)
- **ThreatFox** `POST https://threatfox-api.abuse.ch/api/v1/` `{"query":"get_iocs","days":7}` → `iocs` (`ip:port`→ip, `url`→hostname) และแฮช SHA-256 ใน `malware_samples` → `hashes`; รองรับข้อมูลแบบ array/object และข้ามรูปแบบ IOC/แฮชที่ไม่รู้จัก
- **URLhaus** `GET https://urlhaus.abuse.ch/downloads/hostfile/` → `iocs` domain
- คำขออัปเดต retry สูงสุด 3 ครั้งเฉพาะ network/gateway error ชั่วคราว; `last_update` เปลี่ยนเมื่ออย่างน้อยหนึ่ง feed ตอบสำเร็จเท่านั้น

## 5. การวิเคราะห์ไฟล์ `analyze(path, con) -> (severity|None, [เหตุผล], sha256)`
ลำดับ:
1. ข้ามถ้าขนาด < 64B หรือ > 50MB
2. ถ้านามสกุลไม่ใช่ `SCRIPT_EXT` (`.exe .dll .scr .com .bat .cmd .ps1 .vbs .js`) ต้องขึ้นต้นด้วย `MZ` ไม่งั้นข้าม (เพื่อความเร็ว)
3. คำนวณ SHA-256 → ตรง `hashes` ⇒ **high**
4. อยู่ใน `allow` ⇒ ไม่แจ้ง
5. ไม่ใช่ `SCRIPT_EXT` ⇒ จบ
6. สแกน YARA (`yara_scan`) — severity จาก `meta.severity` (ค่าเริ่มต้น high)
7. Heuristic (เฉพาะ PE): สตริง XWorm (`xworm`, `<xwormmm>`, `xklog` ทั้ง ASCII/UTF-16) **+5**; ชื่อเลียนไฟล์ระบบ (`csrss.exe`, `svchost.exe` …) นอก `%WINDIR%` **+3**; ถ้ามีคะแนนแล้ว: .NET (`mscoree.dll`+`BSJB`) **+1**, อยู่ใน Temp/AppData/ProgramData/Public/Downloads **+1**
8. ผลรวม: YARA high หรือคะแนน ≥5 ⇒ **high**; YARA medium หรือ ≥3 ⇒ **medium**; YARA low ⇒ **low**

การเดินไฟล์ (`walk_files`) ข้าม: `%WINDIR%`, โฟลเดอร์ Windows Defender, `LunaGuard`, และชื่อโฟลเดอร์ใน `SKIP_DIRS` (cache, gpucache, node_modules, .git, `$recycle.bin` …)
โฟลเดอร์ค่าเริ่มต้น: `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, `C:\Users\Public`, `Downloads`, โฟลเดอร์ Startup

## 6. สแกน 5 ขั้น (`cmd_scan(args)`, args: `clean, full, paths, ask`)
1. **ไฟล์** — log `▶ เริ่ม / … ตรวจแล้ว N ไฟล์ (ทุก 3 วิ) / ✔ จบ`; อัปเดต `PROGRESS`; หยุดได้ด้วย `STOP["flag"]`
2. **โปรเซส** — `Get-CimInstance Win32_Process` (PowerShell) → exe ที่ `analyze` = high
3. **จุดฝังตัว** — Registry Run/RunOnce (HKCU/HKLM), Scheduled Tasks (`schtasks /query /fo csv /v`); ชี้ไป high ⇒ high, ชี้ไป path เขียนได้ ⇒ medium
4. **เครือข่าย/DNS** — `netstat -ano -p tcp` เทียบ IP C2 ⇒ high; `ipconfig /displaydns` + `hosts` เทียบโดเมน ⇒ medium
5. **PowerShell history** (`ConsoleHost_history.txt`) — pattern IEX/DownloadString/-enc/FromBase64String/mshta http/CAPTCHA ปลอม/ปิด Defender ⇒ medium
ผลเก็บใน `LAST_SCAN` (`time, files, clean, findings[{sev,kind,target,why}]`) + `history.json` (30 สแกนล่าสุดพร้อมจำนวน HIGH/MEDIUM/LOW และรายละเอียดสูงสุด 100 รายการต่อครั้ง; บันทึกแบบ atomic) Dashboard โหลดผลล่าสุดจากประวัติเมื่อเปิดโปรแกรมใหม่
`--clean` ทำ: `taskkill` โปรเซส → ลบค่า Registry Run → `schtasks /delete` → quarantine ไฟล์ (เฉพาะ high)
CLI: `update | scan [--clean] [--full] [--ask] [--paths ..] | quarantine | restore <id> | add-hash <sha256> | schedule`

## 7. REST API (`luna_dashboard.py`)
ทุก request ต้องมี token (`?t=` หรือ header `X-T`) และ `Host` เป็น `127.0.0.1`/`localhost` ไม่งั้น 403
- `GET /` → dashboard.html; `GET /api/state`; `GET /api/log?since=N`
- `POST /api/update | /api/scan {clean,full,paths} | /api/selftest | /api/restore {id} | /api/key {key} | /api/remove {path} | /api/allow {path} | /api/stop | /api/elevate`
- งานยาวรันเป็น thread เดียว (`S["job"]`); ซ้อนงานได้ 409; stdout ของงานถูกจับเข้า `S["log"]` (ระดับสีจากคำนำหน้า `[HIGH`, `[MEDIUM`, `[+]`, `[!]`, `[PASS`, `[FAIL`)
- `/api/state`: `hashes, iocs, updated, key, yara, admin, job, hist, last, quar, self, prog, n`; ตารางประวัติแสดงเวลา/โหมด/จำนวนไฟล์/ระดับความเสี่ยง และเปิดดูรายละเอียดรายการที่ตรวจพบได้
- `elevate` ใช้ `ShellExecuteW(... "runas" ...)` แล้วปิดโปรเซสเดิม

## 8. UI (`dashboard.html`)
ธีมมืด เขียว/ฟ้า; แท็บ: แดชบอร์ด / กักกัน / Log / ตั้งค่า. องค์ประกอบ id สำคัญ: `ring` (คะแนน), `status`, `s1..s4` (การ์ดสถิติ), `chart`, `layers`, `det` (ตารางตรวจพบ + ปุ่ม กักกัน/ปลอดภัย), `ask` (แบนเนอร์ไฟล์รอตัดสินใจ), `prog`/`busy`/`stopb`, `term` (log), `qt`, `selfr`
poll `/api/state` ทุก 2 วิ และ `/api/log` ทุก 1 วิ; `esc()` escape ข้อความ; path ในปุ่มใช้ `encodeURIComponent` ใน `data-p`
คะแนน = 100 − 30×HIGH − 5×(MEDIUM+LOW)

## 9. การทดสอบ (`python -m unittest -v test_luna`) — 20 ข้อ ผ่านทั้งหมดบน Windows/Linux
แฮชตรง · YARA XWorm · ไม่แจ้งผิดไฟล์ปกติ · ชื่อเลียนระบบ · loader=MEDIUM ไม่ถูก clean · PowerShell history · C2 connection · โดเมนหลอกลวงใน DNS · อัปเดตจาก abuse.ch (mock) · clean ครบวงจร+กู้คืน · MEDIUM→ผู้ใช้กักกัน · allowlist+กัน path ผิด · LOW · log ความคืบหน้า+ข้าม cache · ปุ่มหยุด · ประวัติ scan และ last result หลัง restart พร้อมรายละเอียด · normalize ThreatFox object + hash · retry 502 · update ล้มเหลวไม่เลื่อนเวลา · ไม่มี pywebview ก็ไม่เปิด browser หรือ server · บันทึกภาษาไทย/อังกฤษ/จีนตัวย่อและตรวจ locale keys
วิธี mock: ตั้ง env (`LOCALAPPDATA`, `APPDATA`, `WINDIR` …) **ก่อน import**; แทน `lg.run`, `lg.winreg` (FakeReg), `lg.http`
`PATH_RE` รองรับ path แบบ POSIX และ `user_writable`/`in_windows_dir` แปลง `/`→`\` เพื่อให้เทสต์บน Linux ได้

## 10. ข้อจำกัด / บั๊กที่เคยเจอ (สำคัญ)
- **ยังไม่เคยทดสอบกับมัลแวร์ XWorm จริง** — ตัวอย่างทดสอบเป็นไฟล์จำลอง; ยังไม่ยืนยันความแม่นยำจริง
- ส่วน Windows (netstat/schtasks/ipconfig/registry/CIM) ทดสอบผ่าน mock เท่านั้น
- MalwareBazaar อาจตอบ 502 หรือคืน `no_results` สำหรับบาง tag; ตัวอัปเดต retry gateway/network error ชั่วคราวและแสดงสถานะต่อ query โดยไม่รายงานอัปเดตสำเร็จเมื่อทุก feed ล้มเหลว
- ประวัติเดิมเก็บเพียงยอดรวม จึงกู้รายละเอียดรายรายการย้อนหลังไม่ได้; การสแกนหลังอัปเดตจะบันทึกรายละเอียดสูงสุด 100 รายการต่อครั้ง
- สแกนนานมากเมื่อสแกนโฟลเดอร์ใหญ่/ทั้งไดรฟ์ (แก้บางส่วนด้วยการข้ามไฟล์ไม่ใช่โปรแกรม + cache dirs)
- **บั๊กที่เพิ่งพบและแก้แล้ว**: dashboard ว่างเปล่าเพราะ JS syntax error (เครื่องหมาย `'` ซ้อนในสตริงปุ่ม "รันแบบ Admin"); และสถานะสแกนล่าสุดหายหลังปิดแอปเพราะเก็บไว้ในหน่วยความจำเท่านั้น
- ThreatFox เคยใช้ query `taginfo` และวนข้อมูลโดยสมมติว่าเป็นรายการ ทำให้ API ที่ตอบ object เกิด `string indices must be integers`; เปลี่ยนเป็น `get_iocs` (7 วัน) และ normalize ข้อมูลก่อนบันทึก
- ไม่มี real-time protection, ไม่ตรวจลายเซ็นดิจิทัล, ไม่สแกนหน่วยความจำ/ZIP/USB, ลบ Registry/Task ระดับ MEDIUM รายตัวยังไม่รองรับ

## 11. Roadmap (เรียงตามความสำคัญ) + เกณฑ์ผ่าน
1. **เทสต์ UI ใน repo**: jsdom/Playwright โหลด `dashboard.html` กับ server จริง — เกณฑ์: ไม่มี JS error, nav 4 แท็บ, ring วาดแล้ว, ตารางมีปุ่ม
2. **ตรวจลายเซ็นดิจิทัล** (`Get-AuthenticodeSignature`/WinVerifyTrust) — ไฟล์เซ็นโดยผู้ผลิตที่เชื่อถือได้ลดระดับลง 1 ขั้น; แคชผลตาม sha256
3. **Real-time watcher** (`ReadDirectoryChangesW`/`watchdog`) บน Temp/Downloads/Startup + แจ้งเตือนเดสก์ท็อป
4. **ลบ Registry/Task รายตัว** จากปุ่มใน UI (MEDIUM) พร้อมสำรองค่าก่อนลบและกู้คืนได้
5. **ดึงกฎ YARA ชุมชน** (YARAhub/signature-base) ลง `rules\` อัตโนมัติ + ตรวจ compile ก่อนใช้
6. **ตรวจ USB** (ไดรฟ์ถอดได้: ไฟล์ซ่อน/ `.lnk` ปลอม/สำเนา exe) — XWorm แพร่ทาง USB
7. **สแกนหน่วยความจำ/โปรเซสที่ถูก inject**, สแกน ZIP/RAR, ตรวจ extension/session ของเบราว์เซอร์
8. ตั้งเวลาอัปเดตในตัว (ไม่พึ่ง Task Scheduler), ไอคอนถาดระบบ, ติดตั้ง/เซ็นรับรอง .exe

ข้อกำหนดทุกฟีเจอร์ใหม่: เพิ่มเทสต์ unittest, ไม่ทำลายหลักการ §1, log ภาษาไทยที่ขึ้นต้นด้วย `[+]`/`[!]`/`[HIGH`/`[MEDIUM`

## 12. แหล่งข้อมูลวิจัยฐานข้อมูลไวรัส (ถูกกฎหมาย/สาธารณะ — ใช้ IOC, แฮช, กฎ, รายงาน ไม่ใช่ตัวมัลแวร์)
| แหล่ง | ใช้ทำอะไร |
|---|---|
| **MalwareBazaar** (bazaar.abuse.ch) | แฮช/แท็ก/signature ตัวอย่าง; ต้อง Auth-Key |
| **ThreatFox** (threatfox.abuse.ch) | IOC: IP:port, โดเมน, URL ของ C2 |
| **URLhaus** (urlhaus.abuse.ch) | URL/โฮสต์แจกมัลแวร์ |
| **YARAify / YARAhub** (yaraify.abuse.ch) | กฎ YARA ชุมชนที่เผยแพร่แล้ว |
| **Neo23x0/signature-base**, **Elastic protections-artifacts**, **ReversingLabs yara** (GitHub) | กฎ YARA คุณภาพสูง |
| **Malpedia** (malpedia.caad.fkie.fraunhofer.de) | รายงาน/ข้อมูลตระกูล XWorm |
| **MITRE ATT&CK**, **CISA/ผู้ให้บริการความปลอดภัย** | เทคนิคการฝังตัว/คำแนะนำ |
| **Any.run / Hybrid Analysis / VirusTotal** (รายงานสาธารณะ/API) | พฤติกรรม, mutex, strings, config ของ XWorm |
**ข้อควรระวัง**: อย่าดาวน์โหลด/รันตัวอย่างมัลแวร์บนเครื่องหลัก ถ้าจะวิเคราะห์ต้องใช้ VM แยก ไม่มีเครือข่ายร่วม และเริ่มจากรายงาน/IOC/กฎที่เผยแพร่แล้วก่อนเสมอ

## 13. Prompt ตัวอย่างสำหรับ Copilot
- "อ่าน PROJECT_SPEC.md แล้วเพิ่มเทสต์ UI ด้วย Playwright ตาม §11 ข้อ 1 โดยไม่แก้พฤติกรรม API"
- "เพิ่มการตรวจลายเซ็นดิจิทัลใน `analyze()` ตาม §11 ข้อ 2 พร้อม unittest ที่ mock `run`"
- "ตรวจ `fetch_mb` ว่าทำไมได้แฮช 0 และเพิ่ม fallback ไปยัง export CSV ของ MalwareBazaar"
