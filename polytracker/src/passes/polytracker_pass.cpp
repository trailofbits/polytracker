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
#include "llvm/Support/CommandLine.h"
#include <iostream>
#include <assert.h>     /* assert */
#include <unordered_map>
#include <fstream>

// Can specify any number of ignore lists. 
static llvm::cl::list<std::string> ignore_file_path("ignore-list", llvm::cl::desc("Specify functions to ignore"));
// FIXME (Carson) turn into a bool
static llvm::cl::opt<std::string> generate_ignore_list("gen-list", llvm::cl::desc("When specified, generates an ignore list from bitcode"));

namespace polytracker {

void PolyInstVisitor::visitCmpInst(llvm::CmpInst& CI) {
  //Should never fail
  llvm::Instruction* inst = llvm::dyn_cast<llvm::Instruction>(&CI);
  if (inst->getType()->isVectorTy() || inst->getType()->isStructTy() || inst->getType()->isDoubleTy()) {
    return;
  }
  if (!inst->getType()->isVectorTy() && !inst->getType()->isStructTy()) {
    //Insert after inst.
    llvm::IRBuilder<> IRB(inst->getNextNode());
    llvm::LLVMContext& context = mod->getContext();
    llvm::Type* int32_ty = llvm::Type::getInt32Ty(context);
    auto int32_size = int32_ty->getPrimitiveSizeInBits();
    
    auto inst_type_size = inst->getType()->getPrimitiveSizeInBits();
    auto inst_type = inst->getType();
    // Check size, if the size is not an Int32Ty, then we need to extend or truncate.
    // In LLVM only one instance of a type is created, so checking type equality can be just
    // pointer comparisons.
    if (inst_type == int32_ty || int32_size == inst_type_size || inst->getType()->isPointerTy() || inst->getType()->isDoubleTy()) {
      llvm::Value * hail = IRB.CreateBitCast(inst, int32_ty);
      CallInst * get_taint = IRB.CreateCall(dfsan_get_label, hail);
      CallInst * Call = IRB.CreateCall(taint_cmp_log, get_taint);
    }
    else {
      // Update size
      //llvm::Value * mary;
      //if (inst->getType()->isPointerTy()) {
       // llvm::Value * cast = IRB.CreatePtrToInt(inst, int32_ty);
      //} 
      //inst->getType()->print(llvm::errs());
      llvm::Value * mary = IRB.CreateSExtOrTrunc(inst, int32_ty);
      llvm::Value * hail = IRB.CreateBitCast(mary, int32_ty);
      CallInst * get_taint = IRB.CreateCall(dfsan_get_label, hail);
      CallInst * Call = IRB.CreateCall(taint_cmp_log, get_taint);
    }
  }
}
// TODO (Carson) refactor a bit. 
void PolyInstVisitor::visitBinaryOperator(llvm::BinaryOperator &i) {
  llvm::Instruction* inst = llvm::dyn_cast<llvm::Instruction>(&i);
  if (inst->getType()->isVectorTy() || inst->getType()->isStructTy() || inst->getType()->isDoubleTy()) {
    return;
  }
  if (!inst->getType()->isVectorTy() && !inst->getType()->isStructTy()) {
    llvm::LLVMContext& context = mod->getContext();
    llvm::IRBuilder<> IRB(inst->getNextNode());
    llvm::Type* int32_ty = llvm::Type::getInt32Ty(context);
    auto int32_size = int32_ty->getPrimitiveSizeInBits();
    
    auto inst_type_size = inst->getType()->getPrimitiveSizeInBits();
    auto inst_type = inst->getType();

    // If sizes match, or we can just do pointer casts. 
    if (inst_type == int32_ty || int32_size == inst_type_size || inst->getType()->isPointerTy() || inst->getType()->isDoubleTy()) {
      llvm::Value * hail = IRB.CreateBitCast(inst, int32_ty);
      CallInst * get_taint = IRB.CreateCall(dfsan_get_label, hail);
      CallInst * Call = IRB.CreateCall(taint_op_log, get_taint);
    }
    else {
      // Update size 
      //inst->getType()->print(llvm::errs());
      llvm::Value * mary = IRB.CreateSExtOrTrunc(inst, int32_ty);
      llvm::Value * hail = IRB.CreateBitCast(mary, int32_ty);
      CallInst * get_taint = IRB.CreateCall(dfsan_get_label, hail);
      CallInst * Call = IRB.CreateCall(taint_op_log, get_taint);
    }
  }
}

void PolyInstVisitor::visitCallInst(llvm::CallInst &ci) {
  llvm::Instruction * inst = llvm::dyn_cast<llvm::Instruction>(&ci);
  llvm::Function* caller = inst->getParent()->getParent();
  assert(func_index_map.find(caller->getName().str()) != func_index_map.end());
  func_index_t index = func_index_map[caller->getName().str()];
  // Insert after 
  llvm::IRBuilder<> IRB(inst->getNextNode());
  llvm::LLVMContext& context = mod->getContext();
  llvm::Value *FuncIndex = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context), index, false);
  CallInst *ExitCall = IRB.CreateCall(func_exit_log, {FuncIndex});
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
    analyzeBlock(f, FuncIndex, bb, bb_index++, splitBBs, dominator_tree);
  }

  // FIXME I don't like this
  PolyInstVisitor visitor;
  visitor.mod = mod;
  visitor.dfsan_get_label = dfsan_get_label;
  visitor.taint_cmp_log = taint_cmp_log;
  visitor.taint_op_log = taint_op_log;
  visitor.func_exit_log = func_exit_log;
  visitor.func_index_map = func_index_map;
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
  auto dfsan_get_label_ty = llvm::FunctionType::get(shadow_type, {llvm::Type::getInt32Ty(context)}, false);
  dfsan_get_label = mod.getOrInsertFunction("dfsan_get_label", dfsan_get_label_ty); 
  
}
void PolytrackerPass::readIgnoreFile(const std::string& ignore_file_path) {
  std::ifstream ignore_file(ignore_file_path);
  if (!ignore_file.is_open()) {
    std::cerr << "Error! Could not read: " << ignore_file_path << std::endl;
    exit(1);
  }
  std::string line;
  while (std::getline(ignore_file, line))
  {
    if (line[0] == '#' || line == "\n") {
      continue;
    }
    if (line.find("discard") && line.find("main") == std::string::npos) {
      int start_pos = line.find(':');
      int end_pos = line.find("=");
      // :test=und
      std::string func_name = line.substr(start_pos+1, end_pos-(start_pos+1));
      ignore_funcs[func_name] = true;
    }
  }
}

bool PolytrackerPass::runOnModule(llvm::Module &mod) {
  if (ignore_file_path.getNumOccurrences()) {
    for (auto& file_path : ignore_file_path) {
      readIgnoreFile(file_path);
    }
  }
  initializeTypes(mod);
  bool ret = false;
  func_index_t function_index = 0;
  // Collect functions before instrumenting
  std::vector<llvm::Function *> functions;
  for (auto &func : mod) {
    // Ignore if its in our ignore list
    if (func.hasName()) {
      std::string fname = func.getName().str();
      if (ignore_funcs.find(fname) != ignore_funcs.end()) {
        continue;
      }
    }
    functions.push_back(&func);
    func_index_map[func.getName().str()] = function_index++;
  }
  for (auto func : functions) {
    if (!func || func->isDeclaration()) {
      continue;
    }
    ret = analyzeFunction(func, func_index_map[func->getName().str()]) || ret;
  }
  return ret;
}

char PolytrackerPass::ID = 0;

}; // namespace polytracker

static llvm::RegisterPass<polytracker::PolytrackerPass>
    X("ptrack", "Adds runtime monitoring calls to polytracker runtime",
      false /* Only looks at CFG */, false /* Analysis Pass */);