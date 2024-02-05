rule testRule1
{
    strings:
        $tr1_s1 = "hello_world_1"
        $tr1_s2 = "rule_1_hello_world_2"
        $tr1_s3 = "hello_world_2"

    condition:
        $tr1_s1 or $tr1_s2 or $tr1_s3
}

rule testRule2
{
    strings:
        $tr2_s1 = "rule_2_hello_world_1"
        $tr2_s2 = "rule_2_hello_world_2"

    condition:
        $tr2_s1 or $tr2_s2 
}

