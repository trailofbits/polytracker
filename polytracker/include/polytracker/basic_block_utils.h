#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstrTypes.h"

#include "polytracker/basic_block_types.h"

namespace polytracker {

using llvm::BasicBlock;
using llvm::CallInst;
using llvm::DominatorTree;
using llvm::ReturnInst;
using llvm::TerminatorInst;

BasicBlockType getType(const BasicBlock *bb, const DominatorTree &dt) {
  size_t dominatedPredecessors = 0;
  size_t totalPredecessors = 0;
  size_t dominatingSuccessors = 0;
  size_t totalSuccessors = 0;
  for (const BasicBlock *pred : llvm::predecessors(bb)) {
    ++totalPredecessors;
    if (dt.dominates(bb, pred)) {
      ++dominatedPredecessors;
    }
  }
  for (const BasicBlock *succ : llvm::successors(bb)) {
    ++totalSuccessors;
    if (dt.dominates(succ, bb)) {
      ++dominatingSuccessors;
    }
  }
  BasicBlockType ret = BasicBlockType::STANDARD;
  if (totalSuccessors > 1) {
    ret = ret | BasicBlockType::CONDITIONAL;
  }
  if (&(bb->getParent()->getEntryBlock()) == bb) {
    ret = ret | BasicBlockType::FUNCTION_ENTRY;
  }
  if (dominatedPredecessors > 0 &&
      (totalPredecessors > dominatedPredecessors ||
       hasType(ret, BasicBlockType::FUNCTION_ENTRY))) {
    ret = ret | BasicBlockType::LOOP_ENTRY;
  }
  for (const auto *inst = &bb->front(); inst; inst = inst->getNextNode()) {
    // TODO: Also handle longjmp here
    if (llvm::isa<ReturnInst>(inst)) {
      if (hasType(ret, BasicBlockType::CONDITIONAL)) {
        llvm::errs() << "Error: a basic block in function " << bb->getParent()->getName().data() << " is both a conditional and a function exit. This likely means that the basic block splitting pass failed.\n";
        exit(1);
      }
      ret = ret | BasicBlockType::FUNCTION_EXIT;
    } else if (llvm::isa<CallInst>(inst)) {
      ret = ret | BasicBlockType::FUNCTION_CALL;
    }
    if (llvm::isa<TerminatorInst>(inst)) {
      break;
    }
  }
  if (dominatingSuccessors > 0 &&
      (totalSuccessors > dominatingSuccessors ||
       hasType(ret, BasicBlockType::FUNCTION_EXIT))) {
    ret = ret | BasicBlockType::LOOP_EXIT;
  }
  if (ret != BasicBlockType::STANDARD) {
    // If the BB is anything but standard, it shouldn't have the standard flag
    ret = ret ^ BasicBlockType::STANDARD;
  }
  return ret;
}

}; // namespace polytracker

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_ */
