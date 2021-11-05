#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include "gigafunction/pass/mark_basic_blocks.h"

using namespace llvm;

namespace gigafunction {

PreservedAnalyses BasicBlocksMarkPass::run(Function &f,
                                           FunctionAnalysisManager & /*fam*/) {

  auto &ctx = f.getContext();
  auto i32_ty = IntegerType::get(ctx, 32);
  for (auto &bb : f) {
    auto counter = ConstantInt::get(i32_ty, ++counter_, false);
    MDNode *n = MDNode::get(ctx, ConstantAsMetadata::get(counter));
    bb.front().setMetadata(get_metadata_tag(), n);
  }

  return PreservedAnalyses::all();
}

} // namespace gigafunction
