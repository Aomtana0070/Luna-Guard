// Luna Guard - กฎ YARA ตั้งต้น (แนะนำให้เติมกฎชุมชนไว้ใน %LOCALAPPDATA%\LunaGuard\rules\*.yar)
// severity = high -> กำจัดอัตโนมัติเมื่อใช้ --clean / medium -> แจ้งเตือนเท่านั้น

rule LunaGuard_XWorm_Strong
{
    meta:
        description = "ไฟล์ .NET ที่มีตัวบ่งชี้เฉพาะของ XWorm RAT หลายรายการ"
        severity = "high"
    strings:
        $x1 = "<Xwormmm>" ascii wide nocase
        $x2 = "XWorm V" ascii wide nocase
        $x3 = "Xklog" ascii wide nocase
        $net1 = "mscoree.dll" ascii nocase
        $net2 = "BSJB" ascii
    condition:
        uint16(0) == 0x5A4D and $net1 and $net2 and         2 of ($x*)
}

rule LunaGuard_XWorm_Weak
{
    meta:
        description = "ไฟล์ .NET ขนาดเล็กที่มีคำว่า XWorm (ควรตรวจเอง)"
        severity = "medium"
    strings:
        $x = "XWorm" ascii wide nocase
        $specific1 = "<Xwormmm>" ascii wide nocase
        $specific2 = "XWorm V" ascii wide nocase
        $specific3 = "Xklog" ascii wide nocase
        $net1 = "mscoree.dll" ascii nocase
        $net2 = "BSJB" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and $x and $net1 and $net2 and
        not any of ($specific*)
}

rule LunaGuard_PowerShell_Loader
{
    meta:
        description = "สคริปต์ที่ดึงโค้ดจากเน็ต + ถอดรหัส base64 + ซ่อนหน้าต่าง (แพทเทิร์นแบบ loader)"
        severity = "medium"
    strings:
        $dl = "DownloadString" ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
        $hid = "-WindowStyle Hidden" ascii wide nocase
        $byp = "-ExecutionPolicy Bypass" ascii wide nocase
        $def = "Add-MpPreference" ascii wide nocase
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and
        (($dl and $b64 and ($hid or $byp)) or ($def and ($dl or $b64)))
}

rule LunaGuard_Hidden_PowerShell
{
    meta:
        description = "สคริปต์ซ่อนหน้าต่าง + ข้าม ExecutionPolicy (ไม่แน่ชัด ให้ผู้ใช้ตัดสินใจ)"
        severity = "low"
    strings:
        $hid = "-WindowStyle Hidden" ascii wide nocase
        $byp = "-ExecutionPolicy Bypass" ascii wide nocase
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and $hid and $byp
}
