#ifndef GIGAFUNC_MARK_BASIC_BLOCKS_H
#define GIGAFUNC_MARK_BASIC_BLOCKS_H

#include <llvm/IR/PassManager.h>

#include "gigafunction/types.h"


namespace gigafunction {

  inline llvm::StringRef get_metadata_tag() { return "gigafunc.blockid"; }

  // Marks each basic block with a number.
  // The idea is to be able to recover specific blocks after a run by just using their id.
  // The mark is set in metadata using the string "gigafunc.blockid"
  class BasicBlocksMarkPass : public llvm::PassInfoMixin<BasicBlocksMarkPass> {
  public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);

  private:
    block_id counter_;
  };

}

#endif