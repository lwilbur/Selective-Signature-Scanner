# Selective Signature Scanner
## Summary
The Selective Signature Scanner ("3S") selectively scans portions of files suspected to be malware. Its goal is to improve the runtime of malware signature scanning - such as that used by antivirus software - with minimal loss of accuracy.

## Steps
- [x] Implement functions necessary to use YARA's C API, loading YARA rule files and scanning a directory of files.
- [x] Implement functions necessary to isolate the head and tail of a file.
- [x] Collect a dataset of YARA rules and malware
- [x] Test change in runtime and malware detection accuracy for various size headers and footers.

## Background
* This is an undergraduate thesis, completed for COSC 99.
* This research is intended to verify and expand upon the findings in [this paper](https://doi.org/10.1088/1742-6596/2131/2/022086).

## Usage Guide
### Notes
* Having malware on your system carries inherent risk. Do not work with malware unless you are comfortable with that risk. Consider using a VM or other sandboxing tool.
* All filepaths in the below guide are relative to the main directory, `Selective-Signature-Scanner`.

### Setup 
1. Ensure that you [have YARA downloaded and installed](https://yara.readthedocs.io/en/stable/gettingstarted.html), including its optional crypto libraries.
2. In `Makefile`, update `header` and `libs` to accomodate the location of YARA on your system.
3. Run `make`.
4. Run `./3S -p ./test_set/YARA_rules` to have 3S calculate the 90th and 100th percentile lengths of the YARA rule test set.
5. In `test_set/make_head_tail_files.py`, set `perc90` and `perc100` to the values calculated in step 3.

### Dataset Creation
1. Run `python3 ./test_set/get_malware_by_hash.py`. This downloads zipped malware samples from [YARAify](https://yaraify.abuse.ch/).
2. Run `./test_set/unzip_malware.sh`. This unzips the downloaded samples.
3. Run `python3 ./test_set/make_head_tail_files.py`. This creates the head and tail files which will be scanned by 3S to get our results.

### Result Collection
1. Run `python3 calc_results.py` to test our dataset of YARA rules against each length of header and footer file, using 3S. Results from this run are collated into a `results` file.
