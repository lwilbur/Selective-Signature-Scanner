rule testRule1
{
    strings:
        // 90th percentile should search 20 chars
        $s1 = "match_string_1"          // 14 char
        $s2 = "match_string_2"          // 14 char
        $s3 = "12345678901234567890"    // 20 char
        $s4 = "12345678901234567890"    // 20 char

    condition:
        $s1 or $s2 or $s3 or $s4
}

