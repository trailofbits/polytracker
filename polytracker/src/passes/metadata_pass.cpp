#include "polytracker/metadata_pass.h"

#include "llvm/IR/Module.h"

namespace polytracker {

char MetadataPass::ID = 0;

bool MetadataPass::runOnModule(llvm::Module &mod) {
  auto &ctx = mod.getContext();
  uint64_t inst_num = 0;
  for (auto &func : mod) {
    for (auto &block : func) {
      for (auto &inst : block) {
        // TODO (Carson) encode just as integer metadata later probably
        auto str_val = std::to_string(inst_num++);
        llvm::MDNode *node =
            llvm::MDNode::get(ctx, llvm::MDString::get(ctx, str_val));
        inst.setMetadata("__poly_inst_num", node);
      }
    }
  }

  return false;
}

} // namespace polytracker
static llvm::RegisterPass<polytracker::MetadataPass>
    X("meta", "Adds runtime monitoring calls to polytracker runtime",
      false /* Only looks at CFG */, false /* Analysis Pass */);