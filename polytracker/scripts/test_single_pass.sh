
cp tests/test_object_propagation.cpp .

# Grab the bitcode
# This was -o before
gclang++ -stdlib=libc++ -std=c++17 -static -fPIC -fPIE -pie -Icxx_libs/clean_build/include/c++/v1 -Lcxx_libs/clean_build/lib -g -c test_object_propagation.cpp -Wl,--start-group -lpthread -lc++abi -lc++ -Wl,--end-group

mv test_object_propagation.o testme
get-bc -b testme

# Run it through opt, are there any errors?
opt-10 -load build/share/polytracker/pass/libPolytrackerPass.so -ptrack testme.bc -o output.bc

# Run it through with dfsan
opt-10 -dfsan -dfsan-abilist=polytracker_abilist.txt output.bc -o track.bc
gclang++ -static -fPIC -fPIE -c track.bc
clang++ -stdlib=libc++ -fsanitize=dataflow -pie -fPIC -fPIE -Icxx_libs/clean_build/include/c++/v1 -Lcxx_libs/clean_build/lib -g -o trackme track.o -Wl,--start-group  build/share/polytracker/lib/libPolytracker.a -lc++abi -lc++ -lpthread -Wl,--end-group
