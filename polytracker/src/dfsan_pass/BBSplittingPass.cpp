/*
 * BBSplittingPass.cpp
 *
 *  Created on: Aug 14, 2020
 *      Author: Evan Sultanik, Trail of Bits
 */

#include "polytracker/bb_splitting_pass.h"

using llvm::BasicBlock;

namespace polytracker {

bool BBSplittingPass::runOnBasicBlock(BasicBlock &F) {
  return false;
}

char BBSplittingPass::ID = 0;

};


static llvm::RegisterPass<polytracker::BBSplittingPass> X("bbsplit", "Ensures that all basic blocks contain at most one call or one conditional branch.",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
