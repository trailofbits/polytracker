/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "polytracker/passes/remove_fn_attr.h"

namespace polytracker {

void RemoveFnAttrsPass::visitCallInst(llvm::CallInst &ci) {
  auto fn{ci.getCalledFunction()};
  if (!fn) {
    return;
  }
  auto fname{fn->getName()};
  if (fname.startswith("__dfsw") || fname.startswith("dfs$")) {
    ci.removeAttribute(llvm::AttributeList::FunctionIndex,
                       llvm::Attribute::InaccessibleMemOnly);
    ci.removeAttribute(llvm::AttributeList::FunctionIndex,
                       llvm::Attribute::InaccessibleMemOrArgMemOnly);
    ci.removeAttribute(llvm::AttributeList::FunctionIndex,
                       llvm::Attribute::ReadOnly);
  }
}

llvm::PreservedAnalyses
RemoveFnAttrsPass::run(llvm::Module &mod, llvm::ModuleAnalysisManager &mam) {
  for (auto &fn : mod) {
    auto fname{fn.getName()};
    if (fname.startswith("__dfsw") || fname.startswith("dfs$")) {
      fn.removeFnAttr(llvm::Attribute::InaccessibleMemOnly);
      fn.removeFnAttr(llvm::Attribute::InaccessibleMemOrArgMemOnly);
      fn.removeFnAttr(llvm::Attribute::ReadOnly);
    }
    visit(fn);
  }
  return llvm::PreservedAnalyses::none();
}

} // namespace polytracker