#include "polytracker/basic_block_utils_test.h"
#include "polytracker/bb_splitting_pass.h"
#include "polytracker/polytracker_pass.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Local.h"
#include <iostream>

// TODO (Carson) porting over some changes made in the sqlite branch to here
// That PR is super big anyway

namespace polytracker {


//Creates calls to grab taint for both 
void PolyInstVisitor::logBinaryInst(llvm::Instruction * inst) {
  llvm::IRBuilder<> IRB(inst);
  CallInst * get_taint = IRB.CreateCall(dfsan_get_label, inst);
  CallInst * Call = IRB.CreateCall(taint_op_log, get_taint);
}

void PolyInstVisitor::visitCmpInst(llvm::CmpInst& CI) {
  //std::cout << "Visiting compare!" << std::endl;
  //Should never fail
  llvm::Instruction* inst = llvm::dyn_cast<llvm::Instruction>(&CI);
  //Insert after inst.
  llvm::IRBuilder<> IRB(inst->getNextNode());
  llvm::LLVMContext& context = mod->getContext();
  llvm::Value * inst_val = inst;
  CallInst * get_taint;
  if (inst_val->getType()->isVectorTy()) {
    return;
    //Cast vectory type to its vector element type? 
    //llvm::Value* bit_cast = IRB.CreateBitOrPointerCast(inst_val, inst_val->getType()->getScalarType());
    // Extend that type to an int32 type
    //llvm::Value* extension = IRB.CreateZExtOrBitCast(bit_cast,llvm::Type::getInt32Ty(context));
    //llvm::Value * hail = IRB.CreateBitOrPointerCast(inst, llvm::Type::getInt32PtrTy(context));
    //get_taint = IRB.CreateCall(dfsan_get_label, hail);
  }
  else {
    //llvm::Value* extension = IRB.CreateZExtOrBitCast(inst,llvm::Type::getInt32Ty(context));
    llvm::Value * hail = IRB.CreateBitOrPointerCast(inst, llvm::Type::getInt32PtrTy(context));
    get_taint = IRB.CreateCall(dfsan_get_label, hail);
  }
  //Sign extension magic?
  //get_taint->addParamAttr(0, llvm::Attribute::SExt);
  CallInst * Call = IRB.CreateCall(taint_cmp_log, get_taint);
}

// Pass in function, get context, get the entry block. create the DT?
// Func, func_index, Block, block_index, split_blocks, DT.
bool PolytrackerPass::analyzeBlock(llvm::Function *func,
                                    llvm::Value* func_index,
                                   llvm::BasicBlock* curr_bb,
                                   const bb_index_t &bb_index,
                                   std::vector<llvm::BasicBlock *> &split_bbs,
                                   llvm::DominatorTree &DT) {
  //std::cout << "Visiting function!" << std::endl;
  // FIXME (Evan) Is this correct C++? I'm not sure if the pointer comparison is always valid here 
  // Is the address returned by reference always the same? Then yes it is 
  BasicBlock* entry_block = &func->getEntryBlock();
  llvm::Instruction *Inst = &curr_bb->front();
  llvm::LLVMContext& context = func->getContext();
  llvm::Instruction* insert_point = &(*(func->getEntryBlock().getFirstInsertionPt()));
  llvm::IRBuilder<> IRB(insert_point);
  llvm::Value *func_name = IRB.CreateGlobalStringPtr(func->getName());
  // Add a callback for BB entry
  // we do not need to instrument the entry block of a function
  // because we do that above when we add the function instrumentation
  llvm::Value *BBIndex = llvm::ConstantInt::get(
      llvm::IntegerType::getInt32Ty(context), bb_index, false);

  llvm::Instruction *InsertBefore;
  // Was this one of the new BBs that was split after a function call?
  // If so, set that it is a FUNCTION_RETURN
  bool wasSplit = std::find(split_bbs.cbegin(), split_bbs.cend(), curr_bb) !=
                  split_bbs.cend();
  llvm::Value *BBType = llvm::ConstantInt::get(
      llvm::IntegerType::getInt8Ty(context),
      static_cast<uint8_t>(polytracker::getType(curr_bb, DT) |
                           (wasSplit
                                ? polytracker::BasicBlockType::FUNCTION_RETURN
                                : polytracker::BasicBlockType::UNKNOWN)),
      false);
  if (curr_bb == entry_block) {
    // this is the entrypoint basic block in a function, so make sure the
    // BB instrumentation happens after the function call instrumentation
    // TODO (Carson) I think this should get us the next location.
    InsertBefore = entry_block->getFirstInsertionPt()->getNextNode();
  } else {
    InsertBefore = Inst;
  }
  while (llvm::isa<llvm::PHINode>(InsertBefore) ||
         llvm::isa<llvm::LandingPadInst>(InsertBefore)) {
    // This is a PHI or landing pad instruction,
    // so we need to add the callback afterward
    InsertBefore = InsertBefore->getNextNode();
  }
  //FIXME figure out how to reuse the IRB
  llvm::IRBuilder<> new_IRB(InsertBefore);
  new_IRB.CreateCall(bb_entry_log, {func_name, func_index, BBIndex, BBType});
  return true;
}

/*
We should instrument everything we have bitcode for, right?
If instructions have __polytracker, or they have __dfsan, ignore!
*/
bool PolytrackerPass::analyzeFunction(llvm::Function *f,
                                      const func_index_t &func_index) {
  //std::cout << "Visitng func" << std::endl;
  // Add Function entry
  polytracker::BBSplittingPass bbSplitter;
  llvm::LLVMContext &context = f->getContext();

  llvm::removeUnreachableBlocks(*f);

  std::vector<llvm::BasicBlock *> splitBBs = bbSplitter.analyzeFunction(*f);

  // Instrument function entry here
  llvm::BasicBlock &bb = f->getEntryBlock();
  llvm::Instruction &insert_point = *(bb.getFirstInsertionPt());
  llvm::IRBuilder<> IRB(&insert_point);
  llvm::Value *func_name = IRB.CreateGlobalStringPtr(f->getName());
  llvm::Value *index_val =
      llvm::ConstantInt::get(shadow_type, func_index, false);
  IRB.CreateCall(func_entry_log, {func_name, index_val});

  // Build the dominator tree for this function once blocks are split.
  // Used by the BBSplitting/entry analysis code
  llvm::DominatorTree dominator_tree;
  dominator_tree.recalculate(*f);

  // Collect basic blocks, don't confuse the iterator
  bb_index_t bb_index = 0;
  std::vector<llvm::BasicBlock *> blocks;
  std::vector<llvm::Instruction*> insts;
  for (auto &bb : *f) {
    blocks.push_back(&bb);
    for (auto& inst: bb) {
      insts.push_back(&inst);
    }
  }
  llvm::Value* FuncIndex = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context), func_index, false);
  
  for (auto bb: blocks) {
    analyzeBlock(f, FuncIndex, bb, bb_index, splitBBs, dominator_tree);
  }
  // FIXME I don't like this
  PolyInstVisitor visitor;
  visitor.mod = mod;
  visitor.dfsan_get_label = dfsan_get_label;
  visitor.taint_cmp_log = taint_cmp_log;
  visitor.taint_op_log = taint_op_log;
  for (auto& inst: insts) {
    visitor.visit(inst);
  }

  return true;
}

void PolytrackerPass::initializeTypes(llvm::Module &mod) {
  this->mod = &mod;
  llvm::LLVMContext &context = mod.getContext();
  shadow_type = llvm::IntegerType::get(context, this->shadow_width);

  // Return type, arg types, is vararg
  auto taint_log_fn_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                                 {shadow_type}, false);
  taint_op_log =
      mod.getOrInsertFunction("__polytracker_log_taint_op", taint_log_fn_ty);
  taint_cmp_log =
      mod.getOrInsertFunction("__polytracker_log_taint_cmp", taint_log_fn_ty);

  // Should pass in func_name and uint32_t function index.
  func_entry_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {llvm::Type::getInt8PtrTy(context), shadow_type}, false);
  func_entry_log =
      mod.getOrInsertFunction("__polytracker_log_func_entry", func_entry_type);

  // Should pass in the function index
  auto exit_fn_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                            {shadow_type}, false);
  func_exit_log =
      mod.getOrInsertFunction("__polytracker_log_func_exit", exit_fn_ty);

  llvm::Type *bb_func_args[4] = {llvm::Type::getInt8PtrTy(context), shadow_type,
                                 shadow_type,
                                 llvm::IntegerType::getInt8Ty(context)};
  auto entry_bb_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                             bb_func_args, false);
  bb_entry_log =
      mod.getOrInsertFunction("__polytracker_log_bb_entry", entry_bb_ty);
    
  //This function is how Polytracker works with DFsan
  //dfsan_get_label is a special function that gets instrumented by dfsan and changes its ABI. The return type is a dfsan_label
  //as defined by dfsan
  auto dfsan_get_label_ty = llvm::FunctionType::get(shadow_type, {llvm::Type::getInt32PtrTy(context)}, false);
  dfsan_get_label = mod.getOrInsertFunction("dfsan_get_label", dfsan_get_label_ty); 
  
}

bool PolytrackerPass::runOnModule(llvm::Module &mod) {
  std::cout << "Running on module" << std::endl;
  initializeTypes(mod);
  bool ret = false;
  func_index_t function_index = 0;
  // Collect functions before instrumenting
  std::vector<llvm::Function *> functions;
  for (auto &func : mod) {
    functions.push_back(&func);
  }
  for (auto func : functions) {
    if (!func || func->isDeclaration()) {
      continue;
    }
    ret = analyzeFunction(func, function_index) || ret;
  }
  return ret;
}

char PolytrackerPass::ID = 0;

}; // namespace polytracker

static llvm::RegisterPass<polytracker::PolytrackerPass>
    X("ptrack", "Adds runtime monitoring calls to polytracker runtime",
      false /* Only looks at CFG */, false /* Analysis Pass */);