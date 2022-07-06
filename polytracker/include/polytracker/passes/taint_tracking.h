/*
 * Copyright (c) 2021-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/PassManager.h>

namespace polytracker {

struct TaintTrackingPass : public llvm::PassInfoMixin<TaintTrackingPass>,
                           public llvm::InstVisitor<TaintTrackingPass> {
  llvm::IntegerType *label_ty{nullptr};
  llvm::FunctionCallee taint_start_fn;
  llvm::FunctionCallee cond_br_log_fn;

  void insertCondBrLogCall(llvm::Instruction &inst, llvm::Value *val);
  void insertTaintStartupCall(llvm::Module &mod);

  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void insertLoggingFunctions(llvm::Module &mod);
  void visitGetElementPtrInst(llvm::GetElementPtrInst &gep);
  void visitBranchInst(llvm::BranchInst &bi);
  void visitSwitchInst(llvm::SwitchInst &si);
};

} // namespace polytracker