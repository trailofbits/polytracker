#include "polytracker/metadata_pass.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Metadata.h"
#include <string>

using namespace llvm;

bool MetadataPass::runOnModule(Module &mod) {
  LLVMContext &context = mod.getContext();
  uint64_t inst_num = 0;
  for (auto &func : mod) {
    for (auto &block : func) {
      for (auto &inst : block) {
        // TODO (Carson) encode just as integer metadata later probably
        auto str_val = std::to_string(inst_num++);
        llvm::MDNode *node =
            llvm::MDNode::get(context, llvm::MDString::get(context, str_val));
        inst.setMetadata("__poly_inst_num", node);
      }
    }
  }

  return false;
}