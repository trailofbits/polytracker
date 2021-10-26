#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include "gigafunction/pass/instrument_basic_blocks.h"
#include "gigafunction/pass/mark_basic_blocks.h"

using namespace llvm;

namespace {


ConstantInt* read_block_id(BasicBlock &bb) {
  if (MDNode* n = bb.front().getMetadata(gigafunction::metadata_tag)) {
    auto n0 = cast<ConstantAsMetadata>(n->getOperand(0))->getValue();
    return cast<ConstantInt>(n0);
  }
  errs() << "Warning did not find metadata tag '" << gigafunction::metadata_tag << 
        "' for block in function " << bb.getParent()->getName() << "\n" <<
        " ensure the markbasicblocks-pass have been run previously.";
  return nullptr;
}

// Inserts the following call first in the block (firstins is first instruction
// in basic block) gigafunction_enter_block(thread_id, bid); where thread_id is
// a in the same function frame and bid is the block id (globally unique)
void insert_log_block_enter(Instruction *thread_id_instr, LLVMContext &ctx,
                            Module &mod, Instruction *firstins,
                            ConstantInt* bid) {
  auto thread_state_ty = IntegerType::get(ctx, 8)->getPointerTo();
  auto block_id_ty = IntegerType::get(ctx, sizeof(gigafunction::block_id) * 8);
  auto void_ty = Type::getVoidTy(ctx);
  auto gigafunction_log_bb_enter_ty =
      FunctionType::get(void_ty, {thread_state_ty, block_id_ty}, false);
  auto enter_block_function = mod.getOrInsertFunction(
      "gigafunction_enter_block", gigafunction_log_bb_enter_ty);

  IRBuilder<> irb(firstins);
  irb.CreateCall(enter_block_function, {thread_id_instr, bid});

  outs() << "{block: " << bid->getZExtValue() << ", function: \"" << firstins->getFunction()->getName() << "\"}\n";
}

// Inserts the following call first in the function
// gigafunction_get_thread_id();
// Returns a reference to the return value of that call for
// later objects to use the value
Instruction *insert_get_thread_id_call(LLVMContext &ctx, Module &mod,
                                       Function &f) {
  auto thread_state_ty = IntegerType::get(ctx, 8)->getPointerTo();
  auto gigafunction_get_thread_state_ty =
      FunctionType::get(thread_state_ty, {}, false);
  auto get_thread_state_function = mod.getOrInsertFunction(
      "gigafunction_get_thread_state", gigafunction_get_thread_state_ty);

  BasicBlock &bb = f.getEntryBlock();
  auto block_id = read_block_id(bb);

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
                         call_instruction->getNextNode(), block_id);
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
PreservedAnalyses InstrumentBasicBlocksPass::run(Function &f,
                                            FunctionAnalysisManager & /*fam*/) {

  auto &ctx = f.getContext();
  auto &mod = *f.getParent();

  auto thread_id_alloca = insert_get_thread_id_call(ctx, mod, f);

  BasicBlock &bb = f.getEntryBlock();
  Instruction *func_first_instr = &*bb.getFirstInsertionPt();
  for (auto &bb : f) {
    auto block_first_instr = &*bb.getFirstInsertionPt();
    if (func_first_instr != block_first_instr) {
      // Not entry point block, already covered above
      auto bid = read_block_id(bb);
      insert_log_block_enter(thread_id_alloca, ctx, mod, block_first_instr,
                             bid);
    }
  }

  return PreservedAnalyses::none();
}

} // namespace gigafunction

PassPluginLibraryInfo getBasicBlocksTracePluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "instrumentbasicblocks", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "instrumentbasicblocks") {
                    FPM.addPass(gigafunction::InstrumentBasicBlocksPass());
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
