#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"

#include "polytracker/basic_block_types.h"

namespace polytracker {

using llvm::BasicBlock;
using llvm::DominatorTree;

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
  if (&(bb->getParent()->getEntryBlock()) == bb) {
    ret = ret | BasicBlockType::FUNCTION_ENTRY;
  }
  if (dominatedPredecessors > 0 && totalPredecessors > dominatedPredecessors) {
    ret = ret | BasicBlockType::LOOP_ENTRY;
  }
  if (dominatingSuccessors == 0) {
    if (totalSuccessors > 1) {
      ret = ret | BasicBlockType::CONDITIONAL;
    }
  } else if (totalSuccessors > dominatingSuccessors) {
    ret = ret | BasicBlockType::LOOP_EXIT;
  }
  return ret;
}

}; // namespace polytracker

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_ */
