#include "polytracker/bb_track_pass.h"
#include "polytracker/basic_block_utils_test.h"
#include "polytracker/bb_splitting_pass.h"
// #include "polytracker/thread_pool.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/CtorUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <assert.h> /* assert */
#include <fstream>
#include <iomanip> /* for std::setw */
#include <iostream>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <unordered_map>
#include <unordered_set>

namespace bbtrack {

// Pass in function, get context, get the entry block. create the DT?
// Func, func_index, Block, block_index, split_blocks, DT.
bool BBTrack::analyzeBlock(llvm::Function *func, llvm::BasicBlock *curr_bb,
                           const uint64_t &bb_index,
                           std::vector<llvm::BasicBlock *> &split_bbs,
                           llvm::DominatorTree &DT) {
  llvm::BasicBlock *entry_block = &func->getEntryBlock();
  llvm::Instruction *Inst = &curr_bb->front();
  llvm::LLVMContext &context = func->getContext();
  llvm::Instruction *insert_point =
      &(*(func->getEntryBlock().getFirstInsertionPt()));

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

  auto bb_type = static_cast<uint8_t>(
      polytracker::getType(curr_bb, DT) |
      (wasSplit ? polytracker::BasicBlockType::FUNCTION_RETURN
                : polytracker::BasicBlockType::UNKNOWN));

  llvm::Value *BBType = llvm::ConstantInt::get(
      llvm::IntegerType::getInt8Ty(context), bb_type, false);

  while (llvm::isa<llvm::PHINode>(InsertBefore) ||
         llvm::isa<llvm::LandingPadInst>(InsertBefore)) {
    // This is a PHI or landing pad instruction,
    // so we need to add the callback afterward
    InsertBefore = InsertBefore->getNextNode();
  }

  IRB.SetInsertPoint(InsertBefore);

  auto res = IRB.CreateCall(block_entry_log, {BBIndex, BBType});
  block_global_map[curr_bb] = bb_index;
  block_type_map[bb_index] = bb_type;
  return true;
}

bool BBTrack::analyzeFunction(llvm::Function *f) {
  polytracker::BBSplittingPass bbSplitter;
  llvm::LLVMContext &context = f->getContext();
  std::vector<llvm::BasicBlock *> splitBBs = bbSplitter.analyzeFunction(*f);
  llvm::DominatorTree DT;
  DT.recalculate(*f);
  llvm::BasicBlock &bb = f->getEntryBlock();
  llvm::Instruction &insert_point = *(bb.getFirstInsertionPt());
  llvm::IRBuilder<> IRB(&insert_point);

  uint64_t bb_index = 0;

  std::string fname = f->getName().str();
  if (fname == "main") {
    llvm::Instruction *call = IRB.CreateCall(track_start, {});
  }
  // Collect basic blocks/insts, so we don't modify the container while iterate
  std::unordered_set<llvm::BasicBlock *> blocks;
  for (auto &bb : *f) {
    blocks.insert(&bb);
  }

  for (auto block : splitBBs) {
    blocks.insert(block);
  }

  for (auto bb : blocks) {
    analyzeBlock(f, bb, bb_index++, splitBBs, DT);
  }

  return true;
}

void BBTrack::initializeTypes(llvm::Module &mod) {
  this->mod = &mod;
  llvm::LLVMContext &context = mod.getContext();
}

bool BBTrack::runOnModule(llvm::Module &mod) {
  initializeTypes(mod);

  bool ret = false;

  std::vector<llvm::Function *> functions;
  for (auto &func : mod) {
    functions.push_back(&func);
  }
  for (auto func : functions) {
    if (func->isDeclaration()) {
      continue;
    }
    ret = analyzeFunction(func) || ret;
  }
  return true;
}

char BBTrack::ID = 0;

}; // namespace bbtrack

static llvm::RegisterPass<bbtrack::BBTrack>
    X("bbtrack", "Add calls to log basic blocks and store syscall results",
      false /* Only looks at CFG */, false /* Analysis Pass */);
