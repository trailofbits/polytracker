#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include "gigafunction/pass/tracebasicblocks.h"

using namespace llvm;

namespace {

// Inserts the following call first in the block (firstins is first instruction
// in basic block) gigafunction_enter_block(thread_id, bid); where thread_id is
// a in the same function frame and bid is the block id (globally unique)
void insert_log_block_enter(Instruction *thread_id_instr, LLVMContext &ctx,
                            Module &mod, Instruction *firstins,
                            gigafunction::block_id bid) {
  auto thread_state_ty = IntegerType::get(ctx, 8)->getPointerTo();
  auto block_id_ty = IntegerType::get(ctx, 64);
  auto void_ty = Type::getVoidTy(ctx);
  auto gigafunction_log_bb_enter_ty =
      FunctionType::get(void_ty, {thread_state_ty, block_id_ty}, false);
  auto enter_block_function = mod.getOrInsertFunction(
      "gigafunction_enter_block", gigafunction_log_bb_enter_ty);

  auto bid_value = ConstantInt::get(block_id_ty, bid, false);

  IRBuilder<> irb(firstins);
  irb.CreateCall(enter_block_function, {thread_id_instr, bid_value});

  outs() << "{block: " << bid << ", function: \"" << firstins->getFunction()->getName() << "\"}\n";
}

// Inserts the following call first in the function
// gigafunction_get_thread_id();
// Returns a reference to the return value of that call for
// later objects to use the value
// NOTE: Assumes DominatorTree has been recalculated.
// TODO (hbrodin): Verify needed ^----
Instruction *insert_get_thread_id_call(LLVMContext &ctx, Module &mod,
                                       Function &f,
                                       gigafunction::block_id bid) {
  auto thread_state_ty = IntegerType::get(ctx, 8)->getPointerTo();
  auto gigafunction_get_thread_state_ty =
      FunctionType::get(thread_state_ty, {}, false);
  auto get_thread_state_function = mod.getOrInsertFunction(
      "gigafunction_get_thread_state", gigafunction_get_thread_state_ty);

  BasicBlock &bb = f.getEntryBlock();
  // Find the last alloca inst if any
  Instruction *ip = &*bb.getFirstInsertionPt();
  for (auto &instr : bb) {
    ip = &instr;
    if (!dyn_cast<AllocaInst>(ip))
      break;
  }
  IRBuilder<> irb(ip);
  auto call_instruction = irb.CreateCall(get_thread_state_function, {});
  insert_log_block_enter(call_instruction, ctx, mod,
                         call_instruction->getNextNode(), bid);
  return call_instruction;
}

} // namespace

namespace gigafunction {

  /*
  Insert the following into the function
  void function() {
    ...
    uint64_t thread_state = gigafunction_get_thread_state();
    gigafunction_basic_block_enter(thread_state, 1);
    ...
    gigafunction_basic_block_enter(thread_state, 2);
    ...
    gigafunction_basic_block_enter(thread_state, 3);
    ...
  }

  as a minor optimization the thread_state is not explicitly stored on the stack
  See the files in src/librt for implementation details of invoked functions.
  */
PreservedAnalyses BasicBlocksTracePass::run(Function &f,
                                            FunctionAnalysisManager & /*fam*/) {

  auto &ctx = f.getContext();
  auto &mod = *f.getParent();

  DominatorTree dt;
  dt.recalculate(f);
  auto thread_id_alloca = insert_get_thread_id_call(ctx, mod, f, ++counter_);

  BasicBlock &bb = f.getEntryBlock();
  Instruction *func_first_instr = &*bb.getFirstInsertionPt();
  for (auto &bb : f) {
    auto block_first_instr = &*bb.getFirstInsertionPt();
    if (func_first_instr !=
        block_first_instr) // Not entry point block, already covered above
      insert_log_block_enter(thread_id_alloca, ctx, mod, block_first_instr,
                             ++counter_);
  }

  return PreservedAnalyses::none();
}

} // namespace gigafunction

PassPluginLibraryInfo getBasicBlocksTracePluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "basicblockstrace", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "basicblockstrace") {
                    FPM.addPass(gigafunction::BasicBlocksTracePass());
                    return true;
                  }
                  return false;
                });
          }};
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize HelloWorld when added to the pass pipeline on the
// command line, i.e. via '-passes=hello-world'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getBasicBlocksTracePluginInfo();
}
