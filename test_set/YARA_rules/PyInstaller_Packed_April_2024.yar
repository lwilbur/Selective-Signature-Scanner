rule PyInstaller_Packed_April_2024 {
    meta:
        author = "NDA0N"
        date = "2024-04-20"
        description = "Detects files packed with PyInstaller"
        yarahub_uuid = "c8db161b-4046-40ea-830e-94c82cb602af"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3a272e96b2a6682a76021561514d1906"
    strings:
	$PyInstaller = "PyInstaller" ascii
	$PYZ = "PYZ" ascii
	$pyiboot = "pyiboot01_bootstrap" ascii	
    condition: 
	all of them
}