#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include "gigafunction/pass/mark_basic_blocks.h"

using namespace llvm;

namespace gigafunction {

PreservedAnalyses BasicBlocksMarkPass::run(Function &f,
                                            FunctionAnalysisManager & /*fam*/) {

  auto &ctx = f.getContext();
  auto i32_ty = IntegerType::get(ctx, 32);
  for (auto &bb : f) {
    auto counter = ConstantInt::get(i32_ty, ++counter_, false);
    MDNode* n = MDNode::get(ctx, ConstantAsMetadata::get(counter));
    bb.front().setMetadata(metadata_tag, n);
  }

  return PreservedAnalyses::all();
}

} // namespace gigafunction

PassPluginLibraryInfo getBasicBlocksTracePluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "markbasicblocks", LLVM_VERSION_STRING,
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
          }};
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize HelloWorld when added to the pass pipeline on the
// command line, i.e. via '-passes=hello-world'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getBasicBlocksTracePluginInfo();
}
