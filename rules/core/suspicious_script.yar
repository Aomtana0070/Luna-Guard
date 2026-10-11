rule LunaGuard_Suspicious_Script_Download_Execute
{
    meta:
        family = "script-loader"
        category = "loader"
        threat_name = "Suspicious script download and execution"
        severity = "medium"
        confidence = 65
        author = "Luna Guard project"
        description = "Script combines remote download with dynamic execution"
        reference = ""
        rule_version = "1"
        false_positive_notes = "Administrative deployment scripts can use these APIs; inspect context"
        reviewed = "not independently reviewed"
    strings:
        $download1 = "DownloadString" ascii wide nocase
        $download2 = "Invoke-WebRequest" ascii wide nocase
        $execute1 = "Invoke-Expression" ascii wide nocase
        $execute2 = "FromBase64String" ascii wide nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and
        (1 of ($download*) and 1 of ($execute*))
}
