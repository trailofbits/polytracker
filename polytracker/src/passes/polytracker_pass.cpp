#include "polytracker/polytracker_pass.h"
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
#include <unordered_map>
#include <unordered_set>

// Can specify any number of ignore lists.
static llvm::cl::list<std::string>
    ignore_file_path("ignore-list",
                     llvm::cl::desc("Specify functions to ignore"));
// FIXME (Carson) turn into a bool
static llvm::cl::opt<std::string> generate_ignore_list(
    "gen-list",
    llvm::cl::desc("When specified, generates an ignore list from bitcode"));

static llvm::cl::opt<int> file_id(
    "file-id",
    llvm::cl::desc(
        "When specified, adds a file id to the function_ids in the module"));

namespace polytracker {

bool op_check(llvm::Value *inst) {
  // logOp(&CI, taint_cmp_log);
  if (inst->getType()->isVectorTy() || inst->getType()->isStructTy() ||
      inst->getType()->isArrayTy() || inst->getType()->isDoubleTy() ||
      inst->getType()->isFloatTy() || inst->getType()->isFloatingPointTy() ||
      inst->getType()->isPointerTy()) {
    return true;
  }
  return false;
}

// On binary ops
void PolyInstVisitor::logOp(llvm::Instruction *inst,
                            llvm::FunctionCallee &callback) {
  auto first_operand = inst->getOperand(0);
  auto second_operand = inst->getOperand(1);
  if (op_check(first_operand) || op_check(second_operand)) {
    return;
  }
  llvm::IRBuilder<> IRB(inst->getNextNode());
  llvm::LLVMContext &context = mod->getContext();

  llvm::Value *int_val =
      IRB.CreateSExtOrTrunc(inst->getOperand(0), shadow_type);
  llvm::Value *int_val_two =
      IRB.CreateSExtOrTrunc(inst->getOperand(1), shadow_type);

  if (block_global_map.find(inst->getParent()) == block_global_map.end()) {
    std::cerr << "Error! cmp parent block not in block_map" << std::endl;
    exit(1);
  }
  uint64_t gid = block_global_map[inst->getParent()];
  bb_index_t bindex = gid & 0xFFFF;
  func_index_t findex = (gid >> 32);
  llvm::Value *FuncIndex = llvm::ConstantInt::get(
      llvm::IntegerType::getInt32Ty(context), findex, false);
  llvm::Value *BlockIndex = llvm::ConstantInt::get(
      llvm::IntegerType::getInt32Ty(context), bindex, false);
  CallInst *Call =
      IRB.CreateCall(callback, {int_val, int_val_two, FuncIndex, BlockIndex});
}

void PolyInstVisitor::visitCmpInst(llvm::CmpInst &CI) {
  logOp(&CI, taint_cmp_log);
}

void PolyInstVisitor::visitBinaryOperator(llvm::BinaryOperator &Op) {
  logOp(&Op, taint_op_log);
}

void PolyInstVisitor::visitReturnInst(llvm::ReturnInst &RI) {
  llvm::Instruction *inst = llvm::dyn_cast<llvm::Instruction>(&RI);

  uint64_t gid = block_global_map[RI.getParent()];
  bb_index_t bindex = gid & 0xFFFF;
  // Insert after
  llvm::IRBuilder<> IRB(inst);
  llvm::LLVMContext &context = mod->getContext();
  llvm::Function *caller = inst->getParent()->getParent();
  assert(func_index_map.find(caller->getName().str()) != func_index_map.end());
  func_index_t index = func_index_map[caller->getName().str()];
  llvm::Value *FuncIndex = llvm::ConstantInt::get(
      llvm::IntegerType::getInt32Ty(context), index, false);
  llvm::Value *BlockIndex = llvm::ConstantInt::get(
      llvm::IntegerType::getInt32Ty(context), bindex, false);

  CallInst *ExitCall =
      IRB.CreateCall(func_exit_log, {FuncIndex, BlockIndex, stack_loc});
}

void PolyInstVisitor::visitCallInst(llvm::CallInst &ci) {
  llvm::Instruction *inst = llvm::dyn_cast<llvm::Instruction>(&ci);
  auto called_func = ci.getCalledFunction();
  if (called_func != nullptr) {
    if (called_func->hasName() &&
        called_func->getName().find("polytracker") != std::string::npos) {
      return;
    }
    if (called_func->isIntrinsic()) {
      return;
    }
    if (called_func->hasName()) {
      std::string name = called_func->getName().str();
      if (ignore_funcs.find(name) != ignore_funcs.end()) {
        return;
      }
    }
  }
  llvm::Function *caller = inst->getParent()->getParent();
  assert(func_index_map.find(caller->getName().str()) != func_index_map.end());
  func_index_t index = func_index_map[caller->getName().str()];
  if (block_global_map.find(ci.getParent()) == block_global_map.end()) {
    std::cerr << "Error! Call instruction parent block not in block_map"
              << std::endl;
    exit(1);
  }
  // uint64_t gid = block_global_map[ci.getParent()];
  // bb_index_t bindex = gid & 0xFFFF;
  // // Insert after
  // llvm::IRBuilder<> IRB(inst->getNextNode());
  // llvm::LLVMContext &context = mod->getContext();
  // llvm::Value *FuncIndex = llvm::ConstantInt::get(
  //     llvm::IntegerType::getInt32Ty(context), index, false);
  // llvm::Value *BlockIndex = llvm::ConstantInt::get(
  //     llvm::IntegerType::getInt32Ty(context), bindex, false);

  // CallInst *ExitCall =
  //     IRB.CreateCall(func_exit_log, {FuncIndex, BlockIndex, stack_loc});
}

// Pass in function, get context, get the entry block. create the DT?
// Func, func_index, Block, block_index, split_blocks, DT.
bool PolytrackerPass::analyzeBlock(llvm::Function *func,
                                   const func_index_t &findex,
                                   llvm::BasicBlock *curr_bb,
                                   const bb_index_t &bb_index,
                                   std::vector<llvm::BasicBlock *> &split_bbs,
                                   llvm::DominatorTree &DT) {
  // std::cout << "Visiting function!" << std::endl;
  // FIXME (Evan) Is this correct C++? I'm not sure if the pointer comparison is
  // always valid here Is the address returned by reference always the same?
  // Then yes it is
  BasicBlock *entry_block = &func->getEntryBlock();
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
  // bool wasSplit = false;

  llvm::Value *BBType = llvm::ConstantInt::get(
      llvm::IntegerType::getInt8Ty(context),
      static_cast<uint8_t>(polytracker::getType(curr_bb, DT) |
                           (wasSplit
                                ? polytracker::BasicBlockType::FUNCTION_RETURN
                                : polytracker::BasicBlockType::UNKNOWN)),
      false);

  // llvm::Value *BBType =
  // llvm::ConstantInt::get(llvm::IntegerType::getInt8Ty(context),
  //(uint8_t)polytracker::BasicBlockType::UNKNOWN);
  if (curr_bb == entry_block) {
    // this is the entrypoint basic block in a function, so make sure the
    // BB instrumentation happens after the function call instrumentation
    InsertBefore = entry_block->getFirstNonPHI();
    // Scan for log func, should hit it.
    while (InsertBefore) {
      if (llvm::isa<llvm::CallInst>(InsertBefore)) {
        auto call_inst = llvm::dyn_cast<llvm::CallInst>(InsertBefore);
        if (call_inst->getCalledFunction()->hasName()) {
          std::string name = call_inst->getCalledFunction()->getName().str();
          // If a call instruction is the first inst in the block.
          // if its name has polytracker in it.
          // Iterate to next insertion point.
          if (name.find("polytracker_log_func") != std::string::npos) {
            InsertBefore = InsertBefore->getNextNode();
            break;
          }
        }
      }
      InsertBefore = InsertBefore->getNextNode();
    }
    if (InsertBefore == nullptr) {
      std::cout << "ERROR No log func found!" << std::endl;
      InsertBefore = Inst;
    }
  } else {
    InsertBefore = Inst;
  }
  while (llvm::isa<llvm::PHINode>(InsertBefore) ||
         llvm::isa<llvm::LandingPadInst>(InsertBefore)) {
    // This is a PHI or landing pad instruction,
    // so we need to add the callback afterward
    InsertBefore = InsertBefore->getNextNode();
  }

  // FIXME figure out how to reuse the IRB
  llvm::IRBuilder<> new_IRB(InsertBefore);
  llvm::Value *FuncIndex = llvm::ConstantInt::get(
      llvm::IntegerType::getInt32Ty(context), findex, false);

  auto res =
      new_IRB.CreateCall(bb_entry_log, {func_name, FuncIndex, BBIndex, BBType});
  uint64_t gid = static_cast<uint64_t>(findex) << 32 | bb_index;
  block_global_map[curr_bb] = gid;
  return true;
}

/*
We should instrument everything we have bitcode for, right?
If instructions have __polytracker, or they have __dfsan, ignore!
*/
bool PolytrackerPass::analyzeFunction(llvm::Function *f,
                                      const func_index_t &func_index) {
  // std::cout << "Visitng func" << std::endl;
  // Add Function entry
  polytracker::BBSplittingPass bbSplitter;
  llvm::LLVMContext &context = f->getContext();

  // llvm::removeUnreachableBlocks(*f);

  std::vector<llvm::BasicBlock *> splitBBs = bbSplitter.analyzeFunction(*f);
  // std::vector<llvm::BasicBlock *> splitBBs;
  llvm::DominatorTree DT;
  DT.recalculate(*f);
  // Instrument function entry here
  llvm::BasicBlock &bb = f->getEntryBlock();
  llvm::Instruction &insert_point = *(bb.getFirstInsertionPt());
  llvm::IRBuilder<> IRB(&insert_point);
  llvm::Value *func_name = IRB.CreateGlobalStringPtr(f->getName());
  llvm::Value *index_val =
      llvm::ConstantInt::get(shadow_type, func_index, false);

  bb_index_t bb_index = 0;

  // std::string fname = f->getName().str();
  // if (fname == "main") {
  //   llvm::Instruction *call = IRB.CreateCall(polytracker_start, {});
  //   // IRB.SetInsertPoint(call->getNextNode());
  // }

  llvm::Value *bindex_val =
      llvm::ConstantInt::get(shadow_type, bb_index, false);
  llvm::Value *stack_loc =
      IRB.CreateCall(func_entry_log, {func_name, index_val, bindex_val});

  // Build the dominator tree for this function once blocks are split.
  // Used by the BBSplitting/entry analysis code
  // llvm::DominatorTree dominator_tree;
  // dominator_tree.recalculate(*f);

  // Collect basic blocks, don't confuse the iterator
  std::unordered_set<llvm::BasicBlock *> blocks;
  std::vector<llvm::Instruction *> insts;
  for (auto &bb : *f) {
    blocks.insert(&bb);
    for (auto &inst : bb) {
      if (auto bo = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {
        insts.push_back(bo);
      } else if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        insts.push_back(call);
      } else if (auto cmp = llvm::dyn_cast<llvm::CmpInst>(&inst)) {
        insts.push_back(cmp);
      } else if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
        insts.push_back(ret);
      }
      // insts.push_back(&inst);
    }
  }
  for (auto block : splitBBs) {
    blocks.insert(block);
  }

  for (auto bb : blocks) {
    analyzeBlock(f, func_index, bb, bb_index++, splitBBs, DT);
  }

  // FIXME I don't like this
  PolyInstVisitor visitor;
  visitor.mod = mod;
  visitor.dfsan_get_label = dfsan_get_label;
  visitor.taint_cmp_log = taint_cmp_log;
  visitor.taint_op_log = taint_op_log;
  visitor.func_exit_log = func_exit_log;
  visitor.func_index_map = func_index_map;
  visitor.block_global_map = block_global_map;
  visitor.ignore_funcs = ignore_funcs;
  visitor.shadow_type = shadow_type;
  visitor.stack_loc = stack_loc;
  for (auto &inst : insts) {
    visitor.visit(inst);
  }

  return true;
}

void PolytrackerPass::initializeTypes(llvm::Module &mod) {
  this->mod = &mod;
  llvm::LLVMContext &context = mod.getContext();
  shadow_type = llvm::IntegerType::get(context, this->shadow_width);

  auto polytracker_start_fn_ty =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), {}, false);
  polytracker_start =
      mod.getOrInsertFunction("__polytracker_start", polytracker_start_fn_ty);

  // Return type, arg types, is vararg
  auto taint_log_fn_ty = llvm::FunctionType::get(
      llvm::Type::getVoidTy(context),
      {shadow_type, shadow_type, shadow_type, shadow_type}, false);
  taint_op_log =
      mod.getOrInsertFunction("__polytracker_log_taint_op", taint_log_fn_ty);
  taint_cmp_log =
      mod.getOrInsertFunction("__polytracker_log_taint_cmp", taint_log_fn_ty);

  // Should pass in func_name and uint32_t function index.
  func_entry_type = llvm::FunctionType::get(
      llvm::Type::getInt32Ty(context),
      {llvm::Type::getInt8PtrTy(context), shadow_type, shadow_type}, false);
  func_entry_log =
      mod.getOrInsertFunction("__polytracker_log_func_entry", func_entry_type);

  // Should pass in the function index
  auto exit_fn_ty =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                              {shadow_type, shadow_type, shadow_type}, false);
  func_exit_log =
      mod.getOrInsertFunction("__polytracker_log_func_exit", exit_fn_ty);

  llvm::Type *bb_func_args[4] = {llvm::Type::getInt8PtrTy(context), shadow_type,
                                 shadow_type,
                                 llvm::IntegerType::getInt8Ty(context)};

  auto entry_bb_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context),
                                             bb_func_args, false);
  bb_entry_log =
      mod.getOrInsertFunction("__polytracker_log_bb_entry", entry_bb_ty);

  // This function is how Polytracker works with DFsan
  // dfsan_get_label is a special function that gets instrumented by dfsan and
  // changes its ABI. The return type is a dfsan_label as defined by dfsan
  auto dfsan_get_label_ty =
      llvm::FunctionType::get(shadow_type, shadow_type, false);
  dfsan_get_label =
      mod.getOrInsertFunction("dfsan_get_label", dfsan_get_label_ty);
}

void PolytrackerPass::readIgnoreFile(const std::string &ignore_file_path) {
  std::ifstream ignore_file(ignore_file_path);
  if (!ignore_file.is_open()) {
    std::cerr << "Error! Could not read: " << ignore_file_path << std::endl;
    exit(1);
  }
  std::string line;
  while (std::getline(ignore_file, line)) {
    if (line[0] == '#' || line == "\n") {
      continue;
    }

    if (line.find("discard") != std::string::npos &&
        line.find("main") == std::string::npos) {
      int start_pos = line.find(':');
      int end_pos = line.find("=");
      // :test=und
      std::string func_name =
          line.substr(start_pos + 1, end_pos - (start_pos + 1));
      ignore_funcs[func_name] = true;
    }
  }
}

/// Given a llvm.global_ctors list that we can understand,
/// return a map of the function* for quick lookup
static std::vector<llvm::Function *>
parseGlobalCtors(llvm::GlobalVariable *GV) {
  if (GV->getInitializer()->isNullValue())
    return std::vector<llvm::Function *>();
  llvm::ConstantArray *CA =
      llvm::cast<llvm::ConstantArray>(GV->getInitializer());
  std::vector<llvm::Function *> Result;
  Result.reserve(CA->getNumOperands());
  for (auto &V : CA->operands()) {
    llvm::ConstantStruct *CS = llvm::cast<llvm::ConstantStruct>(V);
    Result.push_back(llvm::dyn_cast<llvm::Function>(CS->getOperand(1)));
  }
  return Result;
}

/// Find the llvm.global_ctors list
static llvm::GlobalVariable *findGlobalCtors(llvm::Module &M) {
  llvm::GlobalVariable *GV = M.getGlobalVariable("llvm.global_ctors");
  if (!GV) {
    std::cerr << "Warning: No constructors found, returning" << std::endl;
    return nullptr;
  }
  return GV;
}

bool PolytrackerPass::runOnModule(llvm::Module &mod) {
  if (ignore_file_path.getNumOccurrences()) {
    for (auto &file_path : ignore_file_path) {
      readIgnoreFile(file_path);
    }
  }
  initializeTypes(mod);

  bool ret = false;
  func_index_t function_index = 0;
  if (file_id) {
    function_index = (file_id << 24) | function_index;
  }
  //   // Collect globals
  // llvm::GlobalVariable* g_ctor = findGlobalCtors(mod);
  // if (g_ctor != nullptr) {
  //   std::vector<llvm::Function*> init_list = parseGlobalCtors(g_ctor);
  // }

  llvm::Function *poly_start =
      llvm::dyn_cast<llvm::Function>(polytracker_start.getCallee());
  if (poly_start == nullptr) {
    std::cerr << "Error: cannot get Function* for polytracker_start"
              << std::endl;
    abort();
  }
  // Append our start function to go last
  llvm::appendToGlobalCtors(mod, poly_start, INT32_MAX, nullptr);

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
  const auto startTime = std::chrono::system_clock::now();
  auto lastUpdateTime = startTime;
  size_t i = 0;
  int lastPercent = -1;
  for (auto func : functions) {
    int percent = static_cast<int>(static_cast<float>(i++) * 100.0 /
                                       static_cast<float>(functions.size()) +
                                   0.5);
    auto currentTime = std::chrono::system_clock::now();
    if (percent > lastPercent ||
        std::chrono::duration_cast<std::chrono::seconds>(currentTime -
                                                         lastUpdateTime)
                .count() >= 5.0 ||
        i >= functions.size()) {
      lastUpdateTime = currentTime;
      auto totalElapsedSeconds =
          std::chrono::duration_cast<std::chrono::seconds>(currentTime -
                                                           startTime)
              .count();
      auto functionsPerSecond = static_cast<float>(i) / totalElapsedSeconds;
      std::cerr << '\r' << std::string(80, ' ') << '\r';
      lastPercent = percent;
      auto funcName = func->getName().str();
      if (funcName.length() > 10) {
        funcName = funcName.substr(0, 7) + "...";
      }
      std::cerr << "Instrumenting: " << std::setfill(' ') << std::setw(3)
                << percent << "% |";
      const int barWidth = 20;
      const auto filledBars = static_cast<int>(
          static_cast<float>(barWidth) * static_cast<float>(percent) / 100.0 +
          0.5);
      const auto unfilledBars = barWidth - filledBars;
      for (size_t iter = 0; iter < filledBars; ++iter) {
        std::cerr << "█";
      }
      std::cerr << std::string(unfilledBars, ' ');
      std::cerr << "| " << i << "/" << functions.size() << " [";
      if (functionsPerSecond == 0) {
        std::cerr << "??:??";
      } else {
        auto remainingSeconds = static_cast<int>(
            static_cast<float>(functions.size() - i) / functionsPerSecond +
            0.5);
        auto remainingMinutes = remainingSeconds / 60;
        remainingSeconds %= 60;
        if (remainingMinutes >= 60) {
          std::cerr << (remainingMinutes / 60) << ":";
          remainingMinutes %= 60;
        }
        std::cerr << std::setfill('0') << std::setw(2) << remainingMinutes
                  << ":";
        std::cerr << std::setfill('0') << std::setw(2) << remainingSeconds;
      }
      std::cerr << ", " << std::setprecision(4) << functionsPerSecond
                << " functions/s]" << std::flush;
    }

    if (!func || func->isDeclaration()) {
      continue;
    }
    ret = analyzeFunction(func, func_index_map[func->getName().str()]) || ret;
    // thread_pool.add_job(&polytracker::PolytrackerPass::analyzeFunction, func,
    // func_index_map[func->getName().str()]);
  }
  std::cerr << std::endl;
  // thread_pool.wait();
  return true;
}

char PolytrackerPass::ID = 0;

}; // namespace polytracker

static llvm::RegisterPass<polytracker::PolytrackerPass>
    X("ptrack", "Adds runtime monitoring calls to polytracker runtime",
      false /* Only looks at CFG */, false /* Analysis Pass */);
