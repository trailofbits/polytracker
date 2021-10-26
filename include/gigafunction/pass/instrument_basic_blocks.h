#ifndef GIGAFUNC_INSTRUMENT_BASIC_BLOCKS_H
#define GIGAFUNC_INSTRUMENT_BASIC_BLOCKS_H

#include <llvm/IR/PassManager.h>

#include "gigafunction/types.h"


namespace gigafunction {


  class InstrumentBasicBlocksPass : public llvm::PassInfoMixin<InstrumentBasicBlocksPass> {
  public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);

  };

}

#endif