#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include "gigafunction/pass/detour_taint_functions.h"
#include "gigafunction/pass/instrument_basic_blocks.h"
#include "gigafunction/pass/mark_basic_blocks.h"
#include "gigafunction/pass/split_basic_blocks.h"

using namespace llvm;

PassPluginLibraryInfo getGigaFuncPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "gigafuncpass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "markbasicblocks") {
                    FPM.addPass(gigafunction::BasicBlocksMarkPass());
                    return true;
                  }
                  return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "instrumentbasicblocks") {
                    FPM.addPass(gigafunction::InstrumentBasicBlocksPass());
                    return true;
                  }
                  return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "splitbasicblocks") {
                    FPM.addPass(gigafunction::SplitBasicBlocksPass());
                    return true;
                  }
                  return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "detourtaintfuncs") {
                    FPM.addPass(gigafunction::DetourTaintFunctionsPass());
                    return true;
                  }
                  return false;
                });
          }};
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize HelloWorld when added to the pass pipeline on the
// command line, i.e. via '-passes=hello-world'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getGigaFuncPluginInfo();
}