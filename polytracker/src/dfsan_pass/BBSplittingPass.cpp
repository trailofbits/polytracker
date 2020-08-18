/*
 * BBSplittingPass.cpp
 *
 *  Created on: Aug 14, 2020
 *      Author: Evan Sultanik, Trail of Bits
 */

#include <string>

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

std::vector<BasicBlock *>
BBSplittingPass::analyzeBasicBlock(BasicBlock &basicBlock) const {
  std::vector<BasicBlock *> newBBs;

  for (Instruction &inst : basicBlock) {
    if (auto call = dyn_cast<CallInst>(&inst)) {
      // Is the call immediately followed by an unconditional branch?
      // if so, that's the only case that is okay:
      Instruction *next = inst.getNextNode();
      if (next == nullptr) {
        continue;
      } else if (auto branch = dyn_cast<BranchInst>(next)) {
        if (branch->isUnconditional()) {
          // The next instruction after the call is an unconditional branch,
          // so it's okay to leave it.
          continue;
        }
      }
      std::string fname;
      if (auto function = call->getCalledFunction()) {
        if (function->hasName()) {
          fname = function->getName().data();
        }
      } else if (auto v = call->getCalledValue()->stripPointerCasts()) {
        if (v->hasName()) {
          fname = v->getName().data();
        }
      }
      // We need to split this BB into a new one after the call
      auto bb = next->getParent();
      // Don't bother logging these common functions, but still split for them
      bool includeFunctionName =
          (fname != "llvm.dbg.declare" && fname != "llvm.dbg.value" &&
           fname != "llvm.lifetime.end.p0i8" && fname != "__assert_fail");
      if (fname.length() == 0 || bb->hasName() || includeFunctionName) {
        llvm::errs() << "Splitting basic block";
        if (bb->hasName()) {
          llvm::errs() << " " << bb->getName().data();
        }
        if (includeFunctionName) {
          llvm::errs() << " after call to " << fname;
        }
        llvm::errs() << "\n";
      }
      newBBs.push_back(bb->splitBasicBlock(next));
    }
  }

  return newBBs;
}

std::vector<BasicBlock *>
BBSplittingPass::analyzeFunction(llvm::Function &function) const {
  std::vector<BasicBlock *> ret;
  for (auto &bb : function) {
    auto newBBs = analyzeBasicBlock(bb);
    ret.insert(ret.end(), std::make_move_iterator(newBBs.begin()),
               std::make_move_iterator(newBBs.end()));
  }
  return ret;
}

bool BBSplittingPass::runOnFunction(Function &function) {
  bool ret = false;
  for (auto &bb : function) {
    ret = !analyzeBasicBlock(bb).empty() || ret;
  }
  return ret;
}

char BBSplittingPass::ID = 0;

}; // namespace polytracker

static llvm::RegisterPass<polytracker::BBSplittingPass>
    X("bbsplit", "Basic Block Control Flow Splitter",
      false /* Only looks at CFG */, false /* Analysis Pass */);
