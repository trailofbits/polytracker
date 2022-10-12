/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/PassManager.h>

#include <unordered_map>

namespace polytracker {

class FunctionTracingPass : public llvm::PassInfoMixin<FunctionTracingPass>,
                            public llvm::InstVisitor<FunctionTracingPass> {
  // Function tracing startup
  llvm::FunctionCallee trace_start_fn;
  // Log entry to a function
  llvm::FunctionCallee func_entry_log_fn;
  // Log returns from a function
  llvm::FunctionCallee func_exit_log_fn;
  // Maps functions to entry logging calls inside them. The return value
  // of these calls is used as a parameter to the return logging function.
  std::unordered_map<llvm::Function *, llvm::CallInst *> log_entry_calls;
  // Helpers
  void declareLoggingFunctions(llvm::Module &mod);

public:
  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void visitReturnInst(llvm::ReturnInst &ri);
};

} // namespace polytracker