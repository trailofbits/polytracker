/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "polytracker/passes/tainted_control_flow.h"

#include <llvm/IR/Attributes.h>
#include <llvm/IR/IRBuilder.h>

#include "polytracker/dfsan_types.h"
#include "polytracker/passes/utils.h"

namespace polytracker {

void TaintedControlFlowPass::insertCondBrLogCall(llvm::Instruction &inst,
                                                 llvm::Value *val) {
  llvm::IRBuilder<> ir(&inst);
  auto dummy_val{val};
  if (inst.getType()->isVectorTy()) {
    dummy_val = ir.CreateExtractElement(val, uint64_t(0));
  }
  ir.CreateCall(cond_br_log_fn, {ir.CreateSExtOrTrunc(dummy_val, label_ty)});
}

llvm::ConstantInt *
TaintedControlFlowPass::get_function_id_const(llvm::Instruction &i) {
  return llvm::IRBuilder<>(&i).getInt32(0);
}

void TaintedControlFlowPass::visitGetElementPtrInst(
    llvm::GetElementPtrInst &gep) {
  llvm::IRBuilder<> ir(&gep);
  for (auto &idx : gep.indices()) {
    if (llvm::isa<llvm::ConstantInt>(idx)) {
      continue;
    }

    auto callret = ir.CreateCall(cond_br_log_fn,
                                 {ir.CreateSExtOrTrunc(idx, ir.getInt64Ty()),
                                  get_function_id_const(gep)});

    idx = ir.CreateSExtOrTrunc(callret, idx->getType());
  }
}

void TaintedControlFlowPass::visitBranchInst(llvm::BranchInst &bi) {
  if (bi.isUnconditional()) {
    return;
  }

  llvm::IRBuilder<> ir(&bi);
  auto cond = bi.getCondition();

  auto callret = ir.CreateCall(
      cond_br_log_fn,
      {ir.CreateSExtOrTrunc(cond, ir.getInt64Ty()), get_function_id_const(bi)});

  bi.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

void TaintedControlFlowPass::visitSwitchInst(llvm::SwitchInst &si) {
  llvm::IRBuilder<> ir(&si);
  auto cond = si.getCondition();

  auto callret = ir.CreateCall(
      cond_br_log_fn,
      {ir.CreateSExtOrTrunc(cond, ir.getInt64Ty()), get_function_id_const(si)});

  si.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

void TaintedControlFlowPass::visitSelectInst(llvm::SelectInst &si) {
  // TODO(hbrodin): Can't handle atm.
  if (si.getType()->isVectorTy()) {
    return;
  }
  llvm::IRBuilder<> ir(&si);
  auto cond = si.getCondition();

  auto callret = ir.CreateCall(
      cond_br_log_fn,
      {ir.CreateSExtOrTrunc(cond, ir.getInt64Ty()), get_function_id_const(si)});

  si.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

void TaintedControlFlowPass::declareLoggingFunctions(llvm::Module &mod) {
  auto &ctx = mod.getContext();
  llvm::IRBuilder<> ir(ctx);
  llvm::AttributeList al;
  al = al.addAttribute(ctx, llvm::AttributeList::FunctionIndex,
                       llvm::Attribute::ReadNone);
  cond_br_log_fn = mod.getOrInsertFunction(
      "__polytracker_log_tainted_control_flow", al, ir.getInt64Ty(),
      ir.getInt64Ty(), ir.getInt32Ty());
}

llvm::PreservedAnalyses
TaintedControlFlowPass::run(llvm::Module &mod,
                            llvm::ModuleAnalysisManager &mam) {
  label_ty = llvm::IntegerType::get(mod.getContext(), DFSAN_LABEL_BITS);
  declareLoggingFunctions(mod);
  for (auto &fn : mod) {
    visit(fn);
  }
  return llvm::PreservedAnalyses::none();
}

} // namespace polytracker