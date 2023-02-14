/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "polytracker/passes/basic_blocks.h"

#include <llvm/IR/Attributes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <spdlog/spdlog.h>

#include "polytracker/dfsan_types.h"
#include "polytracker/passes/utils.h"

namespace polytracker {

// void TaintedControlFlowPass::insertCondBrLogCall(llvm::Instruction &inst,
//                                                  llvm::Value *val) {
//   llvm::IRBuilder<> ir(&inst);
//   auto dummy_val{val};
//   if (inst.getType()->isVectorTy()) {
//     dummy_val = ir.CreateExtractElement(val, uint64_t(0));
//   }
//   ir.CreateCall(cond_br_log_fn, {ir.CreateSExtOrTrunc(dummy_val, label_ty)});
// }

void BasicBlocksLogPass::visitBasicBlock(llvm::BasicBlock &BB) {
  llvm::IRBuilder<> ir(&*(BB.getFirstInsertionPt()));
  auto basic_block_arg = llvm::ConstantInt::get(
      BB.getContext(), llvm::APInt(32, counter++, false));
  ir.CreateCall(basic_blocks_log_fn, {basic_block_arg});
}

void BasicBlocksLogPass::declareLoggingFunctions(llvm::Module &mod) {
  llvm::IRBuilder<> ir(mod.getContext());
  // Assuming there won't be more than 2^32 basic blocks in a program.
  basic_blocks_log_fn = mod.getOrInsertFunction(
      "__polytracker_log_basic_block", ir.getVoidTy(), ir.getInt32Ty());
}

llvm::PreservedAnalyses
BasicBlocksLogPass::run(llvm::Module &mod, llvm::ModuleAnalysisManager &mam) {
  declareLoggingFunctions(mod);
  for (auto &fn : mod) {
    visit(fn);
  }

  return llvm::PreservedAnalyses::none();
}

} // namespace polytracker