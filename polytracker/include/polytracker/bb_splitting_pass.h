/*
 * bb_splitting_pass.h
 *
 *  Created on: Aug 14, 2020
 *      Author: Evan Sultanik, Trail of Bits
 */

#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BB_SPLITTING_PASS_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BB_SPLITTING_PASS_H_

#include <vector>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"

namespace polytracker {

struct BBSplittingPass : public llvm::FunctionPass {
  static char ID;

  BBSplittingPass() : FunctionPass(ID) {}

  std::vector<llvm::BasicBlock *> analyzeBasicBlock(llvm::BasicBlock &bb) const;

  std::vector<llvm::BasicBlock *> analyzeFunction(llvm::Function &function) const;

  bool runOnFunction(llvm::Function &function) override;
};

}; // namespace polytracker

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BB_SPLITTING_PASS_H_ */
