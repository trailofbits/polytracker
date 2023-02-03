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
    file << "\"" << name << "\",\n";
  }

private:
  std::ofstream file;
};
} // namespace detail

namespace {
uint32_t
get_or_add_mapping(uintptr_t key, std::unordered_map<uintptr_t, uint32_t> &m,
                   uint32_t &counter, std::string_view name,
                   polytracker::detail::FunctionMappingJSONWriter *js) {
  if (auto it = m.find(key); it != m.end()) {
    return it->second;
  } else {
    if (js) {
      js->append(name);
    }
    return m[key] = counter++;
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

uint32_t TaintedControlFlowPass::get_block_id(llvm::Instruction &i) {
  auto bb = i.getParent();
  auto bb_address = reinterpret_cast<uintptr_t>(bb);
  return get_or_add_mapping(bb_address, block_ids_, block_counter_, "",
                            nullptr);
}

uint32_t TaintedControlFlowPass::get_function_id(llvm::Instruction &i) {
  auto func = i.getParent()->getParent();
  auto func_address = reinterpret_cast<uintptr_t>(func);
  std::string_view name = func->getName();
  return get_or_add_mapping(func_address, function_ids_, function_counter_,
                            name, function_mapping_writer_.get());
}

llvm::ConstantInt *
TaintedControlFlowPass::get_block_id_const(llvm::Instruction &i) {
  return llvm::ConstantInt::get(i.getContext(),
                                llvm::APInt(32, get_block_id(i), false));
}

llvm::ConstantInt *
TaintedControlFlowPass::get_function_id_const(llvm::Instruction &i) {
  return llvm::ConstantInt::get(i.getContext(),
                                llvm::APInt(32, get_function_id(i), false));
}

void TaintedControlFlowPass::visitGetElementPtrInst(
    llvm::GetElementPtrInst &gep) {
  llvm::IRBuilder<> ir(&gep);
  for (auto &idx : gep.indices()) {
    if (llvm::isa<llvm::ConstantInt>(idx)) {
      continue;
    }

    auto callret = ir.CreateCall(
        cond_br_log_fn, {ir.CreateSExtOrTrunc(idx, ir.getInt64Ty()),
                         get_block_id_const(gep), get_function_id_const(gep)});

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
      cond_br_log_fn, {ir.CreateSExtOrTrunc(cond, ir.getInt64Ty()),
                       get_block_id_const(bi), get_function_id_const(bi)});

  bi.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

void TaintedControlFlowPass::visitSwitchInst(llvm::SwitchInst &si) {
  llvm::IRBuilder<> ir(&si);
  auto cond = si.getCondition();

  auto callret = ir.CreateCall(
      cond_br_log_fn, {ir.CreateSExtOrTrunc(cond, ir.getInt64Ty()),
                       get_block_id_const(si), get_function_id_const(si)});

  si.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

void TaintedControlFlowPass::visitSelectInst(llvm::SelectInst &si) {
  llvm::IRBuilder<> ir(&si);
  auto cond = si.getCondition();

  auto callret = ir.CreateCall(
      cond_br_log_fn, {ir.CreateSExtOrTrunc(cond, ir.getInt64Ty()),
                       get_block_id_const(si), get_function_id_const(si)});

  si.setCondition(ir.CreateSExtOrTrunc(callret, cond->getType()));
}

void TaintedControlFlowPass::declareLoggingFunctions(llvm::Module &mod) {
  llvm::IRBuilder<> ir(mod.getContext());
  cond_br_log_fn = mod.getOrInsertFunction(
      "__polytracker_log_tainted_control_flow",
      llvm::AttributeList::get(
          mod.getContext(),
          {{llvm::AttributeList::FunctionIndex,
            llvm::Attribute::get(mod.getContext(),
                                 llvm::Attribute::ReadNone)}}),
      ir.getInt64Ty(), ir.getInt64Ty(), ir.getInt32Ty(), ir.getInt32Ty());
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

TaintedControlFlowPass::TaintedControlFlowPass()
    : function_mapping_writer_(
          std::make_unique<detail::FunctionMappingJSONWriter>(
              "functionid.json")) {}

TaintedControlFlowPass::~TaintedControlFlowPass() = default;
TaintedControlFlowPass::TaintedControlFlowPass(TaintedControlFlowPass &&) =
    default;
} // namespace polytracker