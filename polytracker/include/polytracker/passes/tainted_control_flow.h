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
  // Helpers
  void insertCondBrLogCall(llvm::Instruction &inst, llvm::Value *val);
  void insertTaintStartupCall(llvm::Module &mod);
  void declareLoggingFunctions(llvm::Module &mod);

  uint32_t get_block_id(llvm::Instruction &i);
  uint32_t get_function_id(llvm::Instruction &i);

  llvm::ConstantInt *get_block_id_const(llvm::Instruction &i);
  llvm::ConstantInt *get_function_id_const(llvm::Instruction &i);

public:
  TaintedControlFlowPass();
  TaintedControlFlowPass(TaintedControlFlowPass &&);
  ~TaintedControlFlowPass();

  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void visitGetElementPtrInst(llvm::GetElementPtrInst &gep);
  void visitBranchInst(llvm::BranchInst &bi);
  void visitSwitchInst(llvm::SwitchInst &si);
  void visitSelectInst(llvm::SelectInst &si);

  std::unordered_map<uintptr_t, uint32_t> block_ids_;
  uint32_t block_counter_{0};

  std::unordered_map<uintptr_t, uint32_t> function_ids_;
  uint32_t function_counter_{0};

  std::unique_ptr<detail::FunctionMappingJSONWriter> function_mapping_writer_;
};

} // namespace polytracker