#!/bin/bash
# Script Name: 1_grep.sh
# Author: Michael Rumler
# Description: Searches a path for a string (like 'struct sk_buff') and returns a list of occurances containing file, line and argument index.

# Configuration
workspace_dir="~/BaWorkspace/"
target_dir="~/linux-source-6.8.0/" #for most scenarious set this to the buildroots linux kernel sources TODO
needle="sk_buff"
grep_results_file="grep_results.txt"

# Get highest run number in workspace_dir
find_highest_run_number() {
    local highest_num=0
    local expanded_workspace_dir=$(eval echo "$workspace_dir")

    # Ensure the base directory exists
    if [[ ! -d "$expanded_workspace_dir" ]]; then
        mkdir -p "$expanded_workspace_dir"
    fi

    # Iterate over all subdirectories
    for dir in "$expanded_workspace_dir"*/ ; do
        # Remove the trailing slash from the directory name
        dir=${dir%/}
        dir=${dir##*/}

        # Check if the directory name is an integer
        if [[ $dir =~ ^[0-9]+$ ]]; then
            if (( dir > highest_num )); then
                highest_num=$dir
            fi
        fi
    done

    echo $highest_num
}

# Prepare the run
run_number=$(find_highest_run_number)
run_number=$((run_number + 1))
run_dir="${workspace_dir}${run_number}/"
expanded_run_dir=$(eval echo "$run_dir")
mkdir ${expanded_run_dir}
echo "Starting run '$run_number'."

# Grep for needle
echo "Grepping for '$needle'. Depending on the target size this may take a while."
expanded_target_dir=$(eval echo "$target_dir")
grep_result=$(grep -FIRn "$needle" $expanded_target_dir)
hits=$(echo "$grep_result" | wc -l)
echo "Found $hits occurances."

echo ""
echo "Hits:"
echo "$grep_result"
echo ""

# Remove code from results
echo "Removing code from grep output."
trimmed_result=$(echo "$grep_result" | awk -F':' '{print $1 ":" $2}')
echo "Removed code from grep output."

echo "Storing grep results in '$grep_results_file'."
echo "$trimmed_result" > ${expanded_run_dir}$grep_results_file
echo "Stored grep results."
