/*
 * BBSplittingPass.cpp
 *
 *  Created on: Aug 14, 2020
 *      Author: Evan Sultanik, Trail of Bits
 */

#include <iostream>

#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"

#include "polytracker/bb_splitting_pass.h"

using llvm::BasicBlock;
using llvm::BranchInst;
using llvm::CallInst;
using llvm::dyn_cast;
using llvm::Function;
using llvm::Instruction;
using llvm::isa;
using llvm::TerminatorInst;

namespace polytracker {

bool BBSplittingPass::analyzeBasicBlock(BasicBlock &basicBlock) const {
  bool modified = false;
  BasicBlock *bb = &basicBlock;

  for (Instruction *inst = &bb->front(); inst && !isa<TerminatorInst>(inst);
       inst = inst->getNextNode()) {
    if (auto call = dyn_cast<CallInst>(inst)) {
      // Is the call immediately followed by an unconditional branch?
      // if so, that's the only case that is okay:
      Instruction *next = inst->getNextNode();
      if (auto branch = dyn_cast<BranchInst>(next)) {
        if (branch->isUnconditional()) {
          // The next instruction after the call is an unconditional branch,
          // so it's okay to leave it.
          continue;
        }
      }
      // We need to split this BB into a new one after the call
      modified = true;
      bb = bb->splitBasicBlock(next);
      std::cout << "Splitting basic block ";
      if (bb->hasName()) {
        std::cout << bb->getName().data();
      }
      std::cout << " after call to "
                << call->getCalledFunction()->getName().data() << std::endl;
    }
    return modified;
  }

  return false;
}

bool BBSplittingPass::runOnFunction(Function &function) {
  bool ret = false;
  for (auto &bb : function.getBasicBlockList()) {
    ret = analyzeBasicBlock(bb) || ret;
  }
  return ret;
}

char BBSplittingPass::ID = 0;

}; // namespace polytracker

static llvm::RegisterPass<polytracker::BBSplittingPass>
    X("bbsplit",
      "Ensures that all basic blocks contain at most one call or one "
      "conditional branch.",
      false /* Only looks at CFG */, false /* Analysis Pass */);
