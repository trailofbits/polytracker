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

namespace polytracker {

struct FunctionTracingPass : public llvm::PassInfoMixin<FunctionTracingPass>,
                             public llvm::InstVisitor<FunctionTracingPass> {
  llvm::FunctionCallee trace_start_fn;
  llvm::FunctionCallee func_entry_log_fn;

  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void insertLoggingFunctions(llvm::Module &mod);
};

} // namespace polytracker