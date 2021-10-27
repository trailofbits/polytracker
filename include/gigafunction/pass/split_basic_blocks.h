#ifndef GIGAFUNCTION_SPLIT_BASIC_BLOCKS_H_
#define GIGAFUNCTION_SPLIT_BASIC_BLOCKS_H_
#include <llvm/IR/PassManager.h>

namespace gigafunction {

  // Splits each basic block into smaller basic blocks that all end with a
  // call or conditional branch, to ensure execution does not return into
  // the same block after a call or conditional branch.
  // More or less an updated version of the polytracker version:
  // https://github.com/trailofbits/polytracker/blob/master/polytracker/src/passes/bb_splitting_pass.cpp
  class SplitBasicBlocksPass : public llvm::PassInfoMixin<SplitBasicBlocksPass> {
  public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);

  private:
  };

}
#endif