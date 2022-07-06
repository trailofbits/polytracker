/*
 * Copyright (c) 2021-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "polytracker/passes/taint_tracking.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <spdlog/spdlog.h>

#include <fstream>
#include <unordered_set>
#include <vector>

#include "polytracker/dfsan_types.h"

static llvm::cl::list<std::string>
    ignore_lists("ignore-lists",
                 llvm::cl::desc("Files that spacify functions to ignore"));

namespace polytracker {

namespace {
using str_set_t = std::unordered_set<std::string>;
using str_vec_t = std::vector<std::string>;

static str_set_t readIgnoreLists(const str_vec_t &paths) {
  str_set_t result;
  for (auto &path : paths) {
    std::ifstream fs(path);
    if (!fs.is_open()) {
      spdlog::error("Could not read: {}", path);
      continue;
    }
    // read file line-by-line
    for (std::string line; std::getline(fs, line);) {
      llvm::StringRef ref(line);
      // ignoring comments and empty lines
      if (ref.startswith("#") || ref == "\n") {
        continue;
      }
      // ignore `main`
      if (ref.contains("main")) {
        continue;
      }
      // process line with `discard` only
      if (ref.contains("discard")) {
        // function name is between ':' and '='
        result.insert(ref.slice(ref.find(':') + 1, ref.find('=')).str());
      }
    }
  }
  return result;
}

} // namespace

void TaintTrackingPass::insertCondBrLogCall(llvm::Instruction &inst,
                                            llvm::Value *val) {
  llvm::IRBuilder<> ir(&inst);
  auto dummy_val = val;
  if (inst.getType()->isVectorTy()) {
    dummy_val = ir.CreateExtractElement(val, uint64_t(0u));
  }
  ir.CreateCall(cond_br_log_fn, {ir.CreateSExtOrTrunc(dummy_val, label_ty)});
}

void TaintTrackingPass::insertTaintStartupCall(llvm::Module &mod) {
  auto func = llvm::cast<llvm::Function>(taint_start_fn.getCallee());
  llvm::appendToGlobalCtors(mod, func, 0);
}

void TaintTrackingPass::visitGetElementPtrInst(llvm::GetElementPtrInst &gep) {
  for (auto &idx : gep.indices()) {
    if (llvm::isa<llvm::ConstantInt>(idx)) {
      continue;
    }
    insertCondBrLogCall(gep, idx);
  }
}

void TaintTrackingPass::visitBranchInst(llvm::BranchInst &bi) {
  if (bi.isUnconditional()) {
    return;
  }
  insertCondBrLogCall(bi, bi.getCondition());
}

void TaintTrackingPass::visitSwitchInst(llvm::SwitchInst &si) {
  insertCondBrLogCall(si, si.getCondition());
}

void TaintTrackingPass::insertLoggingFunctions(llvm::Module &mod) {
  llvm::IRBuilder<> ir(mod.getContext());
  taint_start_fn = mod.getOrInsertFunction("__taint_start", ir.getVoidTy());
  cond_br_log_fn = mod.getOrInsertFunction(
      "__polytracker_log_conditional_branch", ir.getVoidTy(), label_ty);
}

llvm::PreservedAnalyses
TaintTrackingPass::run(llvm::Module &mod, llvm::ModuleAnalysisManager &mam) {
  label_ty = llvm::IntegerType::get(mod.getContext(), DFSAN_LABEL_BITS);
  insertLoggingFunctions(mod);
  auto ignore = readIgnoreLists(ignore_lists);
  for (auto &func : mod) {
    if (ignore.count(func.getName().str())) {
      continue;
    }
    visit(func);
  }
  insertTaintStartupCall(mod);
  return llvm::PreservedAnalyses::none();
}
} // namespace polytracker

llvm::PassPluginLibraryInfo getTaintTrackingInfo() {
  return {LLVM_PLUGIN_API_VERSION, "TaintTracking", LLVM_VERSION_STRING,
          [](llvm::PassBuilder &pb) {
            pb.registerPipelineParsingCallback(
                [](llvm::StringRef name, llvm::ModulePassManager &mpm,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (name == "taint") {
                    mpm.addPass(polytracker::TaintTrackingPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getTaintTrackingInfo();
}