/*
 * bb_splitting_pass.h
 *
 *  Created on: Aug 14, 2020
 *      Author: Evan Sultanik, Trail of Bits
 */

#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BB_SPLITTING_PASS_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BB_SPLITTING_PASS_H_

#include "llvm/IR/BasicBlock.h"
#include "llvm/Pass.h"

namespace polytracker {

struct BBSplittingPass : public llvm::BasicBlockPass {
  static char ID;

  BBSplittingPass() : BasicBlockPass(ID) {}

  bool runOnBasicBlock(llvm::BasicBlock &F) override;
};

};

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BB_SPLITTING_PASS_H_ */
