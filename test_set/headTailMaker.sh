#!/bin/bash

# Lengths
len_90_perc=413
len_100_perc=500
len_1pt25x100=625
len_1pt5x100=750
len_1pt75x100=875
len_2x100=1000

# Create directories
dir_90_perc="mw_uzip_90_perc"
dir_100_perc="mw_uzip_100_perc"
dir_1pt25x100_perc="mw_uzip_1pt25x100_perc"
dir_1pt5x100_perc="mw_uzip_1pt5x100_perc"
dir_1pt75x100_perc="mw_uzip_1pt75x100_perc"
dir_2x100_perc="mw_uzip_2x100_perc"

mkdir "${dir_90_perc}"
mkdir "${dir_100_perc}"
mkdir "${dir_1pt25x100_perc}"
mkdir "${dir_1pt5x100_perc}"
mkdir "${dir_1pt75x100_perc}"
mkdir "${dir_2x100_perc}"

# create head+tail file of each length
for filename in malware_unzipped/*; do
    basename="${filename##*/}"

    outfile="${dir_90_perc}/${basename}_90_perc"
    echo "head -q --bytes "$len_90_perc" $filename > "$outfile""
    echo "tail -q --bytes "$len_90_perc" $filename >> "$outfile""

    outfile="${dir_100_perc}/${basename}_100_perc"
    echo "head -q --bytes "$len_100_perc" $filename > "$outfile""
    echo "tail -q --bytes "$len_100_perc" $filename >> "$outfile""


    outfile="${dir_1pt25x100_perc}/${basename}_1pt25"
    echo "head -q --bytes "$len_1pt25x100" $filename > "$outfile""
    echo "tail -q --bytes "$len_1pt25x100" $filename >> "$outfile""

    outfile="${dir_1pt5x100_perc}/${basename}_1pt5"
    echo "head -q --bytes "$len_1pt5x100" $filename > "$outfile""
    echo "tail -q --bytes "$len_1pt5x100" $filename >> "$outfile""

    outfile="${dir_1pt75x100_perc}/${basename}_1pt75"
    echo "head -q --bytes "$len_1pt75x100" $filename > "$outfile""
    echo "tail -q --bytes "$len_1pt75x100" $filename >> "$outfile""

    outfile="${dir_2x100_perc}/${basename}_2"
    echo "head -q --bytes "$len_2x100" $filename > "$outfile""
    echo "tail -q --bytes "$len_2x100" $filename >> "$outfile""
done
