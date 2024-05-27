#!/bin/bash
# Script Name: 2_joern.sh
# Author: Michael Rumler
# Description: Utilized Joern for a lexical analysis to find functions having the needle defined in the called scala script as an argument.

# Configuration
workspace_dir="~/BaWorkspace/"
target_dir="~/linux-source-6.8.0/" #for most scenarious set this to the buildroots linux kernel sources TODO
grep_results_file="grep_results.txt"
cpg_dir="cpgs/"
joern_results_file="joern_results.txt"
scala_script="search.sc"

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

# Continue the run
run_number=$(find_highest_run_number)
run_dir="${workspace_dir}${run_number}/"
expanded_run_dir=$(eval echo "$run_dir")
echo "Continuing run '$run_number'."

# Initialize an empty array
grep_results=()

# Check if the grep_results_file exists
expanded_grep_results_file=$(eval echo "$run_dir$grep_results_file")
echo "looking for file $expanded_grep_results_file"
if [ -e "$expanded_grep_results_file" ]; then
    # Read the file line by line
    while IFS= read -r grep_result; do
        grep_results+=("$grep_result")
    done < "$expanded_grep_results_file"
else
    echo "File not found: $grep_results_file"
    exit 1
fi

rm -f "$expanded_run_dir$joern_results_file" 2> /dev/null

# Iterate over grep results and process them.
last=""
for grep_result in "${grep_results[@]}"; do
    echo "Handling $grep_result"
      # Create CPG
      target=$(echo "$grep_result" | cut -d ':' -f 1)
      relative_target=$(echo "$target" | cut -d '/' -f 5-)
      cpg_destination="$expanded_run_dir$cpg_dir$relative_target.odb"

    if [ "$last" = "$target" ]; then
        echo "skipping, still the same file."
        continue
    fi
    last="$target"

    directory_path="$(dirname "$cpg_destination")"
    mkdir -p "$directory_path"

    # Generate code property graph
    c2cpg.sh -o $cpg_destination $target

    # Call script interpreter
    joern --script $scala_script --param cpgFile="$cpg_destination" --param outFile="$expanded_run_dir$joern_results_file" --param prefix="$target"
done
