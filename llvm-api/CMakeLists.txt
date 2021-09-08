cmake_minimum_required(VERSION 3.10.2)
project(transformer)

set(CMAKE_FIND_PACKAGE_SORT_ORDER NATURAL)
set(CMAKE_FIND_PACKAGE_SORT_DIRECTION DEC)

set(SOURCE_DIR "transformer")
include_directories(${SOURCE_DIR})

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(MACOSX TRUE)
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
find_package(
  Python3
  COMPONENTS Development
  REQUIRED)
include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARY_DIRS})
add_link_options(${Python3_LINK_OPTIONS})

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

#if(("${LLVM_PACKAGE_VERSION}" VERSION_LESS 9.0.0)
#	OR ("${LLVM_PACKAGE_VERSION}" VERSION_GREATER_EQUAL 12))
#  message(FATAL_ERROR "Unsupported LLVM version: ${LLVM_PACKAGE_VERSION}")
#endif()

include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

find_package(Clang REQUIRED CONFIG)
message(STATUS "Using ClangConfig.cmake in: ${Clang_DIR}")

include_directories(${CLANG_INCLUDE_DIRS})
add_definitions(${CLANG_DEFINITIONS})

set(LIBRARY_LIST
    clangAST
    clangASTMatchers
    clangAnalysis
    clangBasic
    clangDriver
    clangEdit
    clangFrontend
    clangFrontendTool
    clangLex
    clangParse
    clangSema
    clangEdit
    clangRewrite
    clangRewriteFrontend
    clangStaticAnalyzerFrontend
    clangStaticAnalyzerCheckers
    clangStaticAnalyzerCore
    clangCrossTU
    clangIndex
    clangSerialization
    clangToolingCore
    clangToolingInclusions
    clangTooling
		clangToolingRefactoring
		clangTransformer
    clangFormat)

	set (LLVM_LIST
		LLVMWindowsManifest LLVMXRay LLVMLibDriver LLVMDlltoolDriver LLVMCoverage LLVMLineEditor LLVMX86Disassembler LLVMX86AsmParser LLVMX86CodeGen LLVMX86Desc LLVMX86Info LLVMOrcJIT LLVMMCJIT LLVMJITLink LLVMOrcTargetProcess LLVMOrcShared LLVMInterpreter LLVMExecutionEngine LLVMRuntimeDyld LLVMSymbolize LLVMDebugInfoPDB LLVMDebugInfoGSYM LLVMOption LLVMObjectYAML LLVMMCA LLVMMCDisassembler LLVMLTO LLVMPasses LLVMCFGuard LLVMCoroutines LLVMObjCARCOpts LLVMHelloNew LLVMipo LLVMVectorize LLVMLinker LLVMInstrumentation LLVMFrontendOpenMP LLVMFrontendOpenACC LLVMExtensions LLVMDWARFLinker LLVMGlobalISel LLVMMIRParser LLVMAsmPrinter LLVMDebugInfoDWARF LLVMSelectionDAG LLVMCodeGen LLVMIRReader LLVMAsmParser LLVMInterfaceStub LLVMFileCheck LLVMFuzzMutate LLVMTarget LLVMScalarOpts LLVMInstCombine LLVMAggressiveInstCombine LLVMTransformUtils LLVMBitWriter LLVMAnalysis LLVMProfileData LLVMObject LLVMTextAPI LLVMMCParser LLVMMC LLVMDebugInfoCodeView LLVMDebugInfoMSF LLVMBitReader LLVMCore LLVMRemarks LLVMBitstreamReader LLVMBinaryFormat LLVMTableGen LLVMSupport LLVMDemangle)
	#if("${LLVM_PACKAGE_VERSION}" VERSION_LESS 10.0.0)
	#  list(APPEND LIBRARY_LIST clangTransformer clangToolingRefactoring)
	#elseif("${LLVM_PACKAGE_VERSION}" VERSION_GREATER_EQUAL 10.0.0)
	#  list(APPEND LIBRARY_LIST clangTransformer clangToolingRefactoring)
	#endif()

	#if(NOT MACOSX)
  # NOTE(ww): For reasons that are unclear to me, macOS does *not* want Python
  # extensions to link to the Python development libraries directly. Instead, it
  # expects to resolve them dynamically via dynamic_lookup. See
  # target_link_options below.
	set(LIBRARY_LIST ${LIBRARY_LIST} ${Python3_LIBRARIES} ${LLVM_LIST})
	#endif()

add_definitions(-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS)

add_library(${PROJECT_NAME} SHARED ${SOURCE_DIR}/extractor.cpp)

set_target_properties(${PROJECT_NAME}
                      PROPERTIES PREFIX "" OUTPUT_NAME ${PYTHON_MODULE_NAME})

if(MACOSX)
  target_link_libraries(${PROJECT_NAME} ${LIBRARY_LIST})
  # NOTE(ww): See the conditional inclusion above.
	#target_link_options(${PROJECT_NAME} PUBLIC -undefined dynamic_lookup)
  # NOTE(ww): Python extensions on macOS don't use .dylib.
  set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".so")
else()
  target_link_libraries(${PROJECT_NAME} -Wl,--start-group ${LIBRARY_LIST}
                        -Wl,--end-group)
endif()
target_link_libraries(${PROJECT_NAME} pthread m)
