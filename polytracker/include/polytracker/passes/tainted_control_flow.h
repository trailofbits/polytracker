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
#include <unordered_map>

namespace polytracker {
namespace detail {
struct FunctionMappingJSONWriter;
}

class TaintedControlFlowPass
    : public llvm::PassInfoMixin<TaintedControlFlowPass>,
      public llvm::InstVisitor<TaintedControlFlowPass> {
  //
  llvm::IntegerType *label_ty{nullptr};
  // Taint tracking startup
  llvm::FunctionCallee taint_start_fn;
  // Log taint label affecting control flow
  llvm::FunctionCallee cond_br_log_fn;
  // Log enter/leave functions
  llvm::FunctionCallee fn_enter_log_fn;
  llvm::FunctionCallee fn_leave_log_fn;

  // Helpers
  void insertCondBrLogCall(llvm::Instruction &inst, llvm::Value *val);
  void insertTaintStartupCall(llvm::Module &mod);
  void declareLoggingFunctions(llvm::Module &mod);

  llvm::ConstantInt *get_function_id_const(llvm::Function &f);
  llvm::ConstantInt *get_function_id_const(llvm::Instruction &i);

public:
  using function_id = uint32_t;

  TaintedControlFlowPass();
  TaintedControlFlowPass(TaintedControlFlowPass &&);
  ~TaintedControlFlowPass();

  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void visitGetElementPtrInst(llvm::GetElementPtrInst &gep);
  void visitBranchInst(llvm::BranchInst &bi);
  void visitSwitchInst(llvm::SwitchInst &si);
  void visitSelectInst(llvm::SelectInst &si);

  void instrumentFunctionEnter(llvm::Function &func);
  void visitReturnInst(llvm::ReturnInst &ri);

  function_id function_mapping(llvm::Function &func);

  std::unordered_map<uintptr_t, function_id> function_ids_;
  function_id function_counter_{0};

  std::unique_ptr<detail::FunctionMappingJSONWriter> function_mapping_writer_;
};

} // namespace polytracker