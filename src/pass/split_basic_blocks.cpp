#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include "gigafunction/pass/split_basic_blocks.h"

using namespace llvm;

namespace gigafunction {

PreservedAnalyses SplitBasicBlocksPass::run(Function &f, FunctionAnalysisManager & /*fam*/) {
  PreservedAnalyses ret = PreservedAnalyses::all();
  for (auto& bb : f) {
    for (auto& ins : bb) {
      if (auto call = dyn_cast<CallInst>(&ins)) {
        // This is a call, the only call that shall not be followed by
        // a block split is if there is an unconditional branch immediately
        // after the call.
        auto next_ins = ins.getNextNode();
        if (!next_ins)
          continue; // Last instruction in basic block
        if (auto branch_instr = dyn_cast<BranchInst>(next_ins)) {
          if (branch_instr->isUnconditional())
            continue;
        }

        // This is a call instruction, not last in the block and not followed
        // by an unconditional branch. We split here.
        bb.splitBasicBlock(next_ins);
        ret = PreservedAnalyses::none();
      }
    }
  }

  return ret;
}

} // namespace gigafunction

PassPluginLibraryInfo getSplitBasicBlocksPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "splitbasicblocks", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "splitbasicblocks") {
                    FPM.addPass(gigafunction::SplitBasicBlocksPass());
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
  return getSplitBasicBlocksPluginInfo();
}
