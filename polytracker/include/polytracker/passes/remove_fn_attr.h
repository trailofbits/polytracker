/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/PassManager.h>

namespace polytracker {

struct RemoveFnAttrsPass : public llvm::PassInfoMixin<RemoveFnAttrsPass>,
                           public llvm::InstVisitor<RemoveFnAttrsPass> {
  llvm::PreservedAnalyses run(llvm::Module &mod,
                              llvm::ModuleAnalysisManager &mam);
  void visitCallInst(llvm::CallInst &ci);
};
} // namespace polytracker