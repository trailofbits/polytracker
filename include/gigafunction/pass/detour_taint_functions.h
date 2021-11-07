#ifndef DETOUR_TAINT_FUNCTIONS_H
#define DETOUR_TAINT_FUNCTIONS_H

#include <llvm/IR/PassManager.h>
#include <llvm/ADT/StringSet.h>

#include <string>

#include "gigafunction/types.h"


namespace gigafunction {


  // Detours any function listed in the config file into a function that the user can contribute
  // E.g. fopen -> gigafunction_fopen, fread -> gigafunction_fread.
  // It is then possible to register taint sources in gigafunction_fopen/fread.
  //
  class DetourTaintFunctionsPass : public llvm::PassInfoMixin<DetourTaintFunctionsPass> {
  public:
    DetourTaintFunctionsPass();
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);
  private:
    llvm::StringSet<> function_names;

  };

}

#endif