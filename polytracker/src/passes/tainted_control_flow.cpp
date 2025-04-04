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

#include <fstream>

static llvm::cl::list<std::string> ignore_lists(
    "pt-ftrace-ignore-list",
    llvm::cl::desc("File that specifies functions that pt-tcf should ignore"));

namespace polytracker {

namespace {
uint32_t get_or_add_mapping(uintptr_t key,
                            std::unordered_map<uintptr_t, uint32_t> &mapping,
                            uint32_t &counter) {
  if (auto it = mapping.find(key); it != mapping.end()) {
    return it->second;
  } else {
    return mapping[key] = counter++;
  }
}
} // namespace

llvm::ConstantInt *
TaintedControlFlowPass::get_function_id_const(llvm::Function &func) {
  auto func_address = reinterpret_cast<uintptr_t>(&func);
  auto fid = get_or_add_mapping(func_address, function_ids_, function_counter_);
  return llvm::ConstantInt::get(func.getContext(), llvm::APInt(32, fid, false));
}

llvm::ConstantInt *
TaintedControlFlowPass::get_function_id_const(llvm::Instruction &i) {
  return get_function_id_const(*(i.getParent()->getParent()));
}

void 
TaintedControlFlowPass::insertInstrumentation(llvm::Instruction &inst, llvm::Value *val) {
  llvm::IRBuilder<> ir(&inst);
  auto dummy_val{val};
  
  if (llvm::isa<llvm::VectorType>(val->getType())) {
    auto vec = llvm::cast<llvm::VectorType>(val);
    if (llvm::isa<llvm::Constant>(vec.getElementType())) {
      return;
    }

    dummy_val = ir.CreateExtractElement(val, uint64_t(0));
  }

  // logs the label and the function id at this point;
  // data flow has affected control flow here.
  ir.CreateCall(cond_br_log_fn,
          {ir.CreateSExtOrTrunc(dummy_val, label_ty), get_function_id_const(inst)});
}

void TaintedControlFlowPass::visitGetElementPtrInst(
  llvm::GetElementPtrInst &gep) {
  // if an index is a constant, skip it
  for (auto &idx : gep.indices()) {
    if (llvm::isa<llvm::Constant>(idx)) {
      continue;
    }
    insertInstrumentation(gep, idx);
  }
}

// void TaintedControlFlowPass::visitBranchInst(llvm::BranchInst &bi) {
//   if (bi.isUnconditional()) {
//     return;
//   }
//   auto cond = bi.getCondition();
//   insertInstrumentation(bi, cond);
// }

// void TaintedControlFlowPass::visitSwitchInst(llvm::SwitchInst &si) {
//   auto cond = si.getCondition();
//   insertInstrumentation(si, cond);
// }

// void TaintedControlFlowPass::visitSelectInst(llvm::SelectInst &si) {
//   auto cond = si.getCondition();
//   if (llvm::isa<llvm::Constant>(cond)) {
//     return;
//   }
//   insertInstrumentation(si, cond);
// }

// void TaintedControlFlowPass::visitIndirectBrInst(llvm::IndirectBrInst &ibi) {
//   auto addr = ibi.getAddress();
//   if (llvm::isa<llvm::Constant>(addr)) {
//     return;
//   }
//   insertInstrumentation(ibi, addr);
// }

// void TaintedControlFlowPass::visitInvokeInst(llvm::InvokeInst &ii) {
//   auto called = ii.getCalledOperand();
//   if (llvm::isa<llvm::Constant>(called)) {
//     return;
//   }
//   insertInstrumentation(ii, called);
// }

void TaintedControlFlowPass::declareLoggingFunctions(llvm::Module &mod) {
  llvm::LLVMContext *context = &mod.getContext();
  llvm::IRBuilder<> ir(*context);

  cond_br_log_fn = mod.getOrInsertFunction(
      "__polytracker_log_tainted_control_flow",
      llvm::AttributeList::get(
          mod.getContext(),
          {{llvm::AttributeList::FunctionIndex,
            llvm::Attribute::get(mod.getContext(),
                                 llvm::Attribute::ReadNone)}}),
      ir.getInt64Ty(), ir.getInt64Ty(), ir.getInt32Ty());

  enter_log_fn_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(*context), llvm::Type::getInt32Ty(*context),
      llvm::Type::getInt8PtrTy(*context));

  fn_enter_log_fn = mod.getOrInsertFunction("__polytracker_enter_function",
                                            enter_log_fn_type);

  fn_leave_log_fn = mod.getOrInsertFunction("__polytracker_leave_function",
                                            ir.getVoidTy(), ir.getInt32Ty());
}

void TaintedControlFlowPass::instrumentFunctionEnter(llvm::Function &func) {
  if (func.isDeclaration()) {
    return;
  }
  llvm::IRBuilder<> ir(&*func.getEntryBlock().begin());

  ir.CreateCall(fn_enter_log_fn, {get_function_id_const(func),
                                  ir.CreateGlobalStringPtr(func.getName())});
}

void TaintedControlFlowPass::visitReturnInst(llvm::ReturnInst &ri) {
  llvm::IRBuilder<> ir(&ri);
  ir.CreateCall(fn_leave_log_fn, get_function_id_const(ri));
}

llvm::PreservedAnalyses
TaintedControlFlowPass::run(llvm::Module &mod,
                            llvm::ModuleAnalysisManager &mam) {
  label_ty = llvm::IntegerType::get(mod.getContext(), DFSAN_LABEL_BITS);
  declareLoggingFunctions(mod);
  auto fnsToIgnore{readIgnoreLists(ignore_lists)};

  for (auto &fn : mod) {
    auto fname{fn.getName()};
    if (fnsToIgnore.count(fname.str())) {
      continue;
    } else {
      instrumentFunctionEnter(fn);
      visit(fn);
    }
  }

  return llvm::PreservedAnalyses::none();
}

} // namespace polytracker