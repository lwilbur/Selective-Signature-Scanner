rule testRule1
{
    strings:
        // 90th percentile should search 20 chars
        $s1 = "match_string_1"          // 14 char
        $s2 = "match_string_2"          // 14 char

    condition:
        $s1 or $s2
}

