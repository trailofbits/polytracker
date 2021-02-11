
cp baseline.cpp testme.cpp
gclang -c stub.c
# Static, make sure that you pull in all of libcxx 
gclang++ -stdlib=libc++ -static -fPIC -fPIE -I/cxx_libs/clean_build/include/c++/v1 -L/cxx_libs/clean_build/lib -g -o testme.o testme.cpp -Wl,--start-group /cxx_libs/clean_build/lib/libc++.a /cxx_libs/clean_build/lib/libc++abi.a libclang_rt.dfsan-x86_64.a stub.o -ldl -lpthread -Wl,--end-group
#-Wl,--start-group -lpthread -lc++abi -lc++ -Wl,--end-group

#mv test_object_propagation.o testme
get-bc -b testme.o

# Bitcode passes
opt -load build/share/polytracker/pass/libPolytrackerPass.so -ptrack testme.o.bc -o output.bc
opt -dfsan -dfsan-abilist=polytracker_abilist.txt output.bc -o track.bc
opt -O3 track.bc -o track.bc

# Lower into an object to prevent more transform
gclang++ -fPIC -c track.bc

# Link time
gclang++ -pie -L/cxx_libs/clean_build/lib -g -o trackme track.o -Wl,--allow-multiple-definition -Wl,--start-group -lc++abi /cxx_libs/poly_build/lib/libc++.a build/share/polytracker/lib/libPolytracker.a -lpthread -ldl libclang_rt.dfsan-x86_64.a -Wl,--end-group

#-Wl,--allow-multiple-definition
