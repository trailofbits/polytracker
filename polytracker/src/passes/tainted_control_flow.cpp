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
    llvm::cl::desc(
        "File that specifies functions that pt-tcf should ignore"));

namespace polytracker {

namespace detail {
// Helper type to produce the json file of function names by functionid
class FunctionMappingJSONWriter {
public:
  FunctionMappingJSONWriter(std::string_view filename)
      : file(filename.data(), std::ios::binary) {
    file << "[";
  }

  ~FunctionMappingJSONWriter() {
    // Back up and erase the last ",\n"
    file.seekp(-2, std::ios::cur);
    file << "\n]\n";
  }

  void append(std::string_view name) {
    // Will cause an additional ',' but don't care about that right now...
    // The destructor will back up two steps and replace the ',' with a newline
    // and array termination.
    file << "\"" << name << "\",\n";
  }

private:
  std::ofstream file;
};
} // namespace detail

namespace {
  uint32_t get_or_add_mapping(uintptr_t key, std::unordered_map<uintptr_t, uint32_t> &mapping, uint32_t &counter) {
    if (auto it = mapping.find(key); it != mapping.end()) {
      return it->second;
    } else {
      return mapping[key] = counter++;
    }
  }
} // namespace

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
TaintedControlFlowPass::get_function_id_const(llvm::Function &func) {
  auto func_address = reinterpret_cast<uintptr_t>(&func);
  auto fid = get_or_add_mapping(func_address, function_ids_, function_counter_);
  return llvm::ConstantInt::get(func.getContext(), llvm::APInt(32, fid, false));
}

llvm::ConstantInt *
TaintedControlFlowPass::get_function_id_const(llvm::Instruction &i) {
  return get_function_id_const(*(i.getParent()->getParent()));
}

void TaintedControlFlowPass::visitGetElementPtrInst(
    llvm::GetElementPtrInst &gep) {
  llvm::IRBuilder<> ir(&gep);
  for (auto &idx : gep.indices()) {
    if (llvm::isa<llvm::ConstantInt>(idx)) {
      continue;
    }

    // we do not handle VectorTypes yet
    if ((*(idx->getType())).isVectorTy()) {
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

  enter_log_fn_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*context), llvm::Type::getInt32Ty(*context), llvm::Type::getInt8PtrTy(*context));

  fn_enter_log_fn = mod.getOrInsertFunction("__polytracker_enter_function", enter_log_fn_type);

  fn_leave_log_fn = mod.getOrInsertFunction("__polytracker_leave_function", ir.getVoidTy(), ir.getInt32Ty());
}

void TaintedControlFlowPass::instrumentFunctionEnter(llvm::Function &func) {
  if (func.isDeclaration()) {
    return;
  }
  llvm::IRBuilder<> ir(&*func.getEntryBlock().begin());

  ir.CreateCall(fn_enter_log_fn,
                {
                  get_function_id_const(func),
                  ir.CreateGlobalStringPtr(func.getName())
                }
  );
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

TaintedControlFlowPass::TaintedControlFlowPass()
    : function_mapping_writer_(
          std::make_unique<detail::FunctionMappingJSONWriter>(
              "functionid.json")) {}

TaintedControlFlowPass::~TaintedControlFlowPass() = default;
TaintedControlFlowPass::TaintedControlFlowPass(TaintedControlFlowPass &&) =
    default;
} // namespace polytracker