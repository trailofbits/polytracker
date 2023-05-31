#!/usr/bin/bash

# NASSERT/NDEBUG builds "O3"
mkdir release
cd release || exit
polytracker build cmake ../.. \
	-DCMAKE_C_FLAGS="-w -D_POSIX_C_SOURCE=200809L -DCODA_OSS_NO_is_trivially_copyable" \
	-DCMAKE_CXX_FLAGS="-w -D_POSIX_C_SOURCE=200809L -DCODA_OSS_NO_is_trivially_copyable" \
  -DCMAKE_BUILD_TYPE=Debug -DNASSERT=1 -DNDEBUG=1 -DCODA_BUILD_TESTS=OFF

polytracker build cmake --build . -j$(($(nproc)+1)) --target show_nitf++ --config Debug
polytracker extract-bc -o baseO3.bc  modules/c++/nitf/show_nitf++
opt -load "${COMPILER_DIR}/pass/libPolytrackerPass.so" -load-pass-plugin "${COMPILER_DIR}/pass/libPolytrackerPass.so" -passes=pt-tcf -o "after_preoptO3.bc" "baseO3.bc"
echo "Optmize bitcode"
polytracker opt-bc --output O3.bc after_preoptO3.bc
echo "Instrument optimized bitcode"
polytracker instrument-bc --ftrace --taint --output instrumentedO3.bc O3.bc
echo "Lower optimized bitcode"
polytracker lower-bc -t show_nitf++ -o nitro_trackRelease instrumentedO3.bc

cd .. || exit

# O0 build
mkdir debug
cd debug || exit
polytracker build cmake ../.. \
	-DCMAKE_C_FLAGS="-w -D_POSIX_C_SOURCE=200809L -DCODA_OSS_NO_is_trivially_copyable" \
	-DCMAKE_CXX_FLAGS="-w -D_POSIX_C_SOURCE=200809L -DCODA_OSS_NO_is_trivially_copyable" \
  -DCMAKE_BUILD_TYPE=Debug -DCODA_BUILD_TESTS=OFF

polytracker build cmake --build . -j$(($(nproc)+1)) --target show_nitf++ --config Debug
polytracker extract-bc -o baseO0.bc  modules/c++/nitf/show_nitf++

opt -load "${COMPILER_DIR}/pass/libPolytrackerPass.so" -load-pass-plugin "${COMPILER_DIR}/pass/libPolytrackerPass.so" -passes=pt-tcf -o "after_preoptO0.bc" "baseO0.bc"

cp after_preoptO0.bc O0.bc

echo "Instrument non-optimized bitcode"
polytracker instrument-bc --ftrace --taint --output instrumentedO0.bc O0.bc

echo "Lower non-optimized bitcode"
polytracker lower-bc -t show_nitf++ -o nitro_trackDebug instrumentedO0.bc

cd .. || exit

cp release/nitro_trackRelease .
cp debug/nitro_trackDebug .