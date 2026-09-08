/* Two demonstration rules, written so a scan of the bundled sample corpus
 * produces deterministic hits. Real deployments drop their own .yar files here —
 * the sandbox scanner compiles every *.yar found in the rules dir.
 * NOTE: the EICAR rule exists only to prove the detection path works. EICAR is a
 * harmless, globally-standardized *test string*, not malware.
 */
rule EICAR_AV_test_string
{
    meta:
        description = "Standard EICAR anti-malware test file (harmless; proves the AV pipeline works)"
        severity    = "info-test-only"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Script_dropper_indicators
{
    meta:
        description = "Office/HTML dropper markers: auto-run macro + obfuscated PowerShell"
        author      = "SENTINEL-IR demo rules"
    strings:
        $a = /AutoOpen|Document_Open|AutoExec/ nocase
        $b = /shell *\(|ShellExecute|CreateObject *\( *"WScript\.Shell"/ nocase
        $c = /powershell(\.exe)? +(-nop +)?-enc(odedcommand)? +[A-Za-z0-9+\/\n=]{40,}/ nocase
    condition:
        ( $a and $b ) or ( $c and #c > 0 )
}
