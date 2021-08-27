#ifndef POLYTRACKER_INCLUDE_METADATA_PASS_H_
#define POLYTRACKER_INCLUDE_METADATA_PASS_H_

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Pass.h"
#include <unordered_map>
#include <vector>

using namespace llvm;

class MetadataPass : public ModulePass {
  static char ID;
  MetadataPass() : ModulePass(ID) {}
  bool runOnModule(llvm::Module &module) override;
};

#endif
