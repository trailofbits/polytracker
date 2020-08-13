#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"

#include "polytracker/basic_block_types.h"

namespace polytracker {

BasicBlockType getType(const llvm::BasicBlock* bb, const llvm::DominatorTree& dt) {
  return BasicBlockType::UNKNOWN;
}

};

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_UTILS_H_ */
