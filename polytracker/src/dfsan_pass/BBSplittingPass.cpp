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

  for (Instruction *inst = &basicBlock.front();
       inst && !isa<TerminatorInst>(inst); inst = inst->getNextNode()) {
    if (auto call = dyn_cast<CallInst>(inst)) {
      // Is the call immediately followed by an unconditional branch?
      // if so, that's the only case that is okay:
      Instruction *next = inst->getNextNode();
      if (next == nullptr) {
        continue;
      } else if (auto branch = dyn_cast<BranchInst>(next)) {
        if (branch->isUnconditional()) {
          // The next instruction after the call is an unconditional branch,
          // so it's okay to leave it.
          continue;
        }
      }
      // We need to split this BB into a new one after the call
      modified = true;
      std::cout << "Splitting basic block";
      auto bb = next->getParent();
      if (bb->hasName()) {
        std::cout << " " << bb->getName().data();
      }
      if (auto function = call->getCalledFunction()) {
        if (function->hasName()) {
          std::cout << " after call to " << function->getName().data();
        }
      } else if (auto v = call->getCalledValue()->stripPointerCasts()) {
        if (v->hasName()) {
          std::cout << " after call to " << v->getName().data();
        }
      }
      std::cout << std::endl;
      bb->splitBasicBlock(next);
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
    X("bbsplit", "Basic Block Control Flow Splitter",
      false /* Only looks at CFG */, false /* Analysis Pass */);
