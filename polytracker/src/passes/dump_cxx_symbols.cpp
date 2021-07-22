#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Pass.h"
#include <iostream>
#include <unordered_map>
#include <vector>

struct DumpPass : public llvm::ModulePass {
  static char ID;
  DumpPass() : ModulePass(ID) {}
  bool runOnModule(llvm::Module &mod) override;
};

bool DumpPass::runOnModule(llvm::Module &mod) {
  std::unordered_map<llvm::Function *, bool> seen;
  for (auto &func : mod) {
    if (seen[&func] == true) {
      continue;
    }
    seen[&func] = true;
    if (func.hasName()) {
      std::string fname = func.getName().str();
      std::cout << "func:" << fname << "=discard" << std::endl;
      std::cout << "func:" << fname << "=uninstrumented" << std::endl;
    }
  }
  return false;
}

char DumpPass::ID = 0;

static llvm::RegisterPass<DumpPass> Y("dump",
                                      "Dumps out symbols from llvm IR bitcode",
                                      false /* Only looks at CFG */,
                                      false /* Analysis Pass */);