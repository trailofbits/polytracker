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
#include <llvm/Support/CommandLine.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <spdlog/spdlog.h>

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

// void TaintedControlFlowPass::visitGetElementPtrInst(llvm::GetElementPtrInst
// &gep) {
//   for (auto &idx : gep.indices()) {
//     if (llvm::isa<llvm::ConstantInt>(idx)) {
//       continue;
//     }
//     insertCondBrLogCall(gep, idx);
//   }
// }

void TaintedControlFlowPass::visitBranchInst(llvm::BranchInst &bi) {
  if (bi.isUnconditional()) {
    return;
  }

  auto cond = bi.getCondition();
  if (auto cmp = dyn_cast<llvm::CmpInst>(cond)) {
    if (cmp->isIntPredicate()) {
      llvm::IRBuilder<> ir(cmp);
      auto num_operands = cmp->getNumOperands();
      for (auto i=0;i<num_operands;i++) {
        auto srcop = cmp->getOperand(i);
        // Ignore constants
        if (llvm::isa<llvm::ConstantInt>(srcop)) {
          continue;
        }
        auto srcty = srcop->getType();
        auto new_srcop = srcop;
        if (srcty->isPointerTy()) {
          new_srcop = ir.CreatePtrToInt(srcop, ir.getInt64Ty());
        }

        auto bb = bi.getParent();
        auto bb_address = reinterpret_cast<uintptr_t>(bb);
        uint32_t block_id;
        if (auto bid_iter = block_ids_.find(bb_address); bid_iter != block_ids_.end()) {
          block_id = bid_iter->second;
        } else {
          block_id = block_counter_++;
          block_ids_[bb_address] = block_counter_;
        }

        auto basic_block_arg = llvm::ConstantInt::get(bb->getContext(), llvm::APInt(32, block_id, false));
        auto callret = ir.CreateCall(cond_br_log_fn, {ir.CreateSExtOrTrunc(new_srcop, ir.getInt64Ty()), basic_block_arg});

        llvm::Value* new_dstop = callret;
        if (new_srcop != srcop) {
          new_dstop = ir.CreateIntToPtr(callret, srcty);
        }
        cmp->setOperand(i, ir.CreateSExtOrTrunc(new_dstop, srcty));
      }
    }
  }
  // auto callret = ir.CreateCall(cond_br_log_fn, ir.CreateSExtOrTrunc(cond, label_ty));
  // bi.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

// void TaintedControlFlowPass::visitSwitchInst(llvm::SwitchInst &si) {
//   insertCondBrLogCall(si, si.getCondition());
// }

void TaintedControlFlowPass::declareLoggingFunctions(llvm::Module &mod) {
  llvm::IRBuilder<> ir(mod.getContext());
  cond_br_log_fn = mod.getOrInsertFunction(
      "__polytracker_log_tainted_control_flow",
      llvm::AttributeList::get(
          mod.getContext(),
          {{llvm::AttributeList::FunctionIndex, llvm::Attribute::get(mod.getContext(), llvm::Attribute::ReadNone)}}),
      ir.getInt64Ty(), ir.getInt64Ty(), ir.getInt32Ty());
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