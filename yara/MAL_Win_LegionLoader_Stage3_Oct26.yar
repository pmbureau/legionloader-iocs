rule MAL_Win_LegionLoader_Stage3_Oct26
{
    meta:
        description = "Detects the LegionLoader in memory downloader by the 16-byte RC4 keys protecting its C2 config table, or by the decrypted nfront.php/nback.php gate paths plus its hardcoded Vivaldi User-Agent"
        author = "pmbureau"
        date = "2026-10-07"
        hash = "2b91747995cd21dd0bb6c8447f50e5323e4a70b58f077f4944ed25378c5bca0e"

    strings:
        // Byte matching: RC4 keys in .data. 
        $key_c2cfg = { 01 64 E3 A0 07 25 EF C1 8B A8 2A 30 A9 E3 2D 9D }  // decrypts littleforlot.com, nfront.php, nback.php, powershell
        $key_ua    = { 06 BC 47 0E 06 70 9A 38 F7 C1 24 55 06 8E 15 66 }  // decrypts the User-Agent

        // String matching: plaintext after RC4 decryption, they match a memory dump / unpacked samples.
        $php_front = "nfront.php" ascii
        $php_back  = "nback.php" ascii
        $ua        = "Chrome/114.0.0.0 Safari/537.36 Vivaldi/5.3.2679.68" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($key_*) or
            (any of ($php_*) and $ua)
        )
}
