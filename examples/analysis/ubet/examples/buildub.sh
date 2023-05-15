#/bin/bash
mkdir debug release
cd debug
polytracker build clang++ -o ub -std=c++20 -O0 ../ub.cpp
polytracker instrument-targets --taint --ftrace ub

cd ../release
polytracker build clang++ -o ub -std=c++20 -O3 ../ub.cpp
polytracker instrument-targets --taint --ftrace ub
cd ..