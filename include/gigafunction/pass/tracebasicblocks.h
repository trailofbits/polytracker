#ifndef GIGAFUNC_TRACEBASICBLOCKS_H
#define GIGAFUNC_TRACEBASICBLOCKS_H

#include <llvm/IR/PassManager.h>

#include "gigafunction/types.h"


namespace gigafunction {


  class BasicBlocksTracePass : public llvm::PassInfoMixin<BasicBlocksTracePass> {
  public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);

  private:
    block_id counter_;
  };

}

#endif