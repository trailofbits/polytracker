/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "polytracker/passes/function_tracing.h"
#include "polytracker/passes/utils.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/CommandLine.h>

static llvm::cl::list<std::string> ignore_lists(
    "pt-ftrace-ignore-list",
    llvm::cl::desc(
        "File that specifies functions that pt-ftrace should ignore"));

namespace polytracker {

void FunctionTracingPass::declareLoggingFunctions(llvm::Module &mod) {
  llvm::IRBuilder<> ir(mod.getContext());
  func_entry_log_fn =
      mod.getOrInsertFunction("__polytracker_log_func_entry", ir.getInt16Ty(),
                              ir.getInt8PtrTy(), ir.getInt16Ty());
  func_exit_log_fn = mod.getOrInsertFunction("__polytracker_log_func_exit",
                                             ir.getVoidTy(), ir.getInt16Ty());
}

void FunctionTracingPass::visitReturnInst(llvm::ReturnInst &ri) {
  llvm::IRBuilder<> ir(&ri);
  ir.CreateCall(func_exit_log_fn, log_entry_calls[ri.getFunction()]);
}

llvm::PreservedAnalyses
FunctionTracingPass::run(llvm::Module &mod, llvm::ModuleAnalysisManager &mam) {
  declareLoggingFunctions(mod);
  auto ignore{readIgnoreLists(ignore_lists)};
  for (auto &fn : mod) {
    auto fname{fn.getName()};
    if (fn.isDeclaration() || ignore.count(fname.str())) {
      continue;
    }
    llvm::IRBuilder<> ir(&*fn.getEntryBlock().begin());
    auto fname_ptr{ir.CreateGlobalStringPtr(fname)};
    log_entry_calls[&fn] = ir.CreateCall(
        func_entry_log_fn, {fname_ptr, ir.getInt16(fname.size())});
    visit(fn);
  }
  return llvm::PreservedAnalyses::none();
}

} // namespace polytracker