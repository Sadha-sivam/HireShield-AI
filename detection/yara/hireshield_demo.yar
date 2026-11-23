rule HireShield_Test_Indicator
{
    meta:
        description = "Synthetic marker for HireShield test cases; not a malware signature"
        author = "HireShield AI"
    strings:
        $marker = "HIRESHIELD_TEST_MARKER" ascii
    condition:
        $marker
}
