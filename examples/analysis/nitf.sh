#!/usr/bin/env bash

# See README.md for help.
# Improvements and suggestions are welcome!
# kelly.kaoudis@trailofbits.com, last updated Nov 2022

function analyse {
    mkdir output
    for nitf in FAW/test_files/nitf/*; do
        echo "-------"
        directory=`basename ${nitf}`

        if [ ! -d output/${directory} ]; then
            mkdir output/$directory
        fi

        for nitro_name in $@; do
            echo "Parsing ${nitf} with ${nitro_name}..."

            outfile=output/${directory}/${nitro_name}_output.txt
            ${nitro_name}/build/modules/c++/nitf/show_nitf++ $nitf > $outfile

            echo "--------" > $outfile

            /usr/bin/time \
                -o /dev/tty -v \
                ${nitro_name}/build/modules/c++/nitf/show_nitf++ $nitf >/dev/null 2>&1

            echo "bash time: "
            TIMEFORMAT='%6R sec %6U usermode cpu-seconds %6S system cpu-seconds'; time ${nitro_name}/build/modules/c++/nitf/show_nitf++ $nitf >/dev/null 2>&1
        done

        for output_i in output/${directory}/*; do
            for output_j in output/${directory}/*; do
                if cmp -s "$output_i" "$output_j"; then
                    continue
                else
                    echo "contents of ${output_i} and ${output_j} differed; using comm to compare further..."
                    comm --check-order -3 $output_i $output_j
                fi
            done
        done
    done
    echo "done! see individual output files in output/"
}


if [ ! -d FAW ]; then
    echo "getting Galois FAW test nitf files..."
    mkdir FAW && cd FAW
    git init && git remote add origin https://github.com/GaloisInc/FAW.git
    git config core.sparseCheckout true
    echo "/test_files/nitf" >> .git/info/sparse-checkout
    git pull origin master
fi

dpkg-query -s time > /dev/null 2>&1
if [ $? -eq 1 ]; then
    echo "installing GNU 'time' package..."
    apt-get install time
fi

if [ ! -d output ]; then
    analyse $@
else
    read -p "Hey! output/ already exists. Delete it entirely and start over? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    if [ -n $confirm ]; then
        echo "okay, *removing* ALL previous output..."
        rm -rf output
        analyse $@
    fi
fi