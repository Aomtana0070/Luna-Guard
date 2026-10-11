rule LunaGuard_PE_Packer_Section_Names
{
    meta:
        family = "packed-file"
        category = "evasion"
        threat_name = "Possible packed PE"
        severity = "low"
        confidence = 25
        author = "Luna Guard project"
        description = "PE contains section-name markers commonly associated with packers"
        reference = ""
        rule_version = "1"
        false_positive_notes = "Section names can be copied or appear in benign packed software; this is only a weak indicator"
        reviewed = "not independently reviewed"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $mpress = "MPRESS" ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 64MB and
        (($upx0 and $upx1) or $mpress)
}
