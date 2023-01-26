/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/PassManager.h>

namespace polytracker {

class BasicBlocksLogPass : public llvm::PassInfoMixin<BasicBlocksLogPass>,
                          public llvm::InstVisitor<BasicBlocksLogPass> {

  // Log taint label affecting control flow
  llvm::FunctionCallee basic_blocks_log_fn;

  // Helpers
  void declareLoggingFunctions(llvm::Module &mod);

public:
  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
   void visitBasicBlock(llvm::BasicBlock &BB);

  uint32_t counter{0};
};

} // namespace polytracker