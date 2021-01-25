
cp tests/test_object_propagation.cpp .
# Grab the bitcode
gclang -stdlib=libc++ -fPIC -pie -Icxx_libs/clean_build/include/c++/v1 -Lcxx_libs/clean_build/lib -g -o testme test_object_propagation.cpp -lc++abi -lc++
get-bc -b testme
# Run it through opt, are there any errors?
opt-10 -load build/share/polytracker/pass/libPolytrackerPass.so -ptrack testme.bc -o output.bc
# Run it through with dfsan
opt-10 -dfsan -dfsan-abilist=polytracker_abilist.txt output.bc -o track.bc

