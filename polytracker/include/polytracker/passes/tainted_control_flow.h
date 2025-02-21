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

class TaintedControlFlowPass
    : public llvm::PassInfoMixin<TaintedControlFlowPass>,
      public llvm::InstVisitor<TaintedControlFlowPass> {
  //
  llvm::IntegerType *label_ty{nullptr};
  // Log taint label affecting control flow
  llvm::FunctionCallee cond_br_log_fn;

  // Helpers
  void insertCondBrLogCall(llvm::Instruction &inst, llvm::Value *val);
  void declareLoggingFunctions(llvm::Module &mod);

  llvm::ConstantInt *get_function_id_const(llvm::Instruction &i);

public:
  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void visitGetElementPtrInst(llvm::GetElementPtrInst &gep);
  void visitBranchInst(llvm::BranchInst &bi);
  void visitSwitchInst(llvm::SwitchInst &si);
  void visitSelectInst(llvm::SelectInst &si);
};

} // namespace polytracker