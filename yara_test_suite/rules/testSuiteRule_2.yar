rule testRule2
{
    strings:
        // 90th percentile should search 20 chars
        $s1 = "12345678901234567890"    // 20 char
        $s2 = "12345678901234567890"    // 20 char

    condition:
        $s1 or $s2
}

