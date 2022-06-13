#pragma once

#include "llvm/Pass.h"

namespace polytracker {

struct MetadataPass : public llvm::ModulePass {
  static char ID;
  MetadataPass() : ModulePass(ID) {}
  bool runOnModule(llvm::Module &module) override;
};

} // namespace polymeta
