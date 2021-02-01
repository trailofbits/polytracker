
cp dfsan_baseline.cpp testme.cpp
# Grab the bitcode
# This was -o before
gclang++ -stdlib=libc++ -fPIC -fPIE -Icxx_libs/clean_build/include/c++/v1 -g -c testme.cpp 
#-Wl,--start-group -lpthread -lc++abi -lc++ -Wl,--end-group

#mv test_object_propagation.o testme
get-bc -b testme.o

# Run it through opt, are there any errors?
opt-10 -load build/share/polytracker/pass/libPolytrackerPass.so -ptrack testme.o.bc -o output.bc

# Run it through with dfsan
opt-10 -dfsan -dfsan-abilist=polytracker_abilist.txt output.bc -o track.bc
clang++ -static -fPIC -fPIE -c track.bc

echo "LOWERING"
clang++ -stdlib=libc++ -fsanitize=dataflow -pie -fPIC -fPIE -Icxx_libs/clean_build/include/c++/v1 -Lcxx_libs/clean_build/lib -g -o trackme track.o -Wl,--allow-multiple-definition -Wl,--start-group -lc++abi cxx_libs/poly_build/lib/libc++.a build/share/polytracker/lib/libPolytracker.a -lpthread -Wl,--end-group

#-Wl,--allow-multiple-definition
