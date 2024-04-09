# Selective Signature Scanner
## Summary
The Selective Signature Scanner ("3S") selectively scans portions of files suspected to be malware. Its goal is to improve the runtime of malware signature scanning - such as that used by antivirus software - with minimal loss of accuracy.

## Steps
- [x] Implement functions necessary to use YARA's C API, loading YARA rule files and scanning a directory of files.
- [x] Implement functions necessary to isolate the head and tail of a file.
- [ ] Collect a dataset of YARA rules and malware
- [ ] Test change in runtime and malware detection accuracy for various size headers and footers.

## Background
* This is an undergraduate thesis, completed for COSC 99.
* This research is intended to verify and expand upon the findings in [this paper](https://doi.org/10.1088/1742-6596/2131/2/022086).

