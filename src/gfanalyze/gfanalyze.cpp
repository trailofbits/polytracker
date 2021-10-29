
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include<algorithm>
#include <stack>
#include <unordered_map>

#include "gigafunction/types.h"
#include "gigafunction/pass/mark_basic_blocks.h"
#include "gigafunction/traceio/trace_reader.h"

using namespace llvm;

namespace gigafunction {
using blockindex_t = std::unordered_map<block_id, BasicBlock*>;




// TODO (hbrodin): This was stolen from instrument_basic_blocks.cpp create lib.
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
struct call_state {
  BasicBlock *alloca_bb;
  BasicBlock *bind_ret_bb;
  ValueToValueMapTy vm;
  call_state(BasicBlock *allocabb = nullptr, BasicBlock *bindretbb = nullptr)
   : alloca_bb(allocabb), bind_ret_bb(bindretbb) {}
};

using callstack_ty = std::stack<call_state>;

// Create a branch from->to. If last instr in from is a branch of any kind update it to to
void ensure_branch(BasicBlock *from, BasicBlock *to) {
    if (auto branch = dyn_cast<BranchInst>(&from->getInstList().back())) {
      if (branch->isUnconditional()) {
        branch->setOperand(0, to);
        return; // Early abort, just change branch target
      }
      // drop conditional branch
      branch->removeFromParent();
    }

    // insert branch
    IRBuilder<> irb(from);
    irb.CreateBr(to);
}

BasicBlock * create_func_args_block(LLVMContext &ctx, Function* gf, Function* f, BasicBlock *prev_bb, callstack_ty &cs) {
  //auto bb = BasicBlock::Create(ctx, "alloca_bb", gf);
  auto bb = BasicBlock::Create(ctx, Twine(f->getName()).concat("-args"), gf);
  IRBuilder<> irb(bb);

  for (auto &arg : f->args()) {
    auto alloca = irb.CreateAlloca(arg.getType());
    cs.top().vm[&arg] = alloca;
  }

  // If a return value, create alloca to store it as well
  auto ret_ty = f->getReturnType();
  if (!ret_ty->isVoidTy())
    irb.CreateAlloca(ret_ty);

  if (prev_bb)
    ensure_branch(prev_bb, bb);
  return bb;
}

// Top level bind-args is different since we don't have the call
// just propagate the 'gigafunction' arguments into the alloca block
BasicBlock *create_top_bind_args_bb(LLVMContext &ctx, Function *gf, BasicBlock *alloc_bb) {
  auto bind_args_bb = BasicBlock::Create(ctx,  Twine(alloc_bb->getName()).concat("-bind-topargs"), gf);
  IRBuilder<> irb(bind_args_bb);

  auto alloca_ins = &alloc_bb->front();
  for (auto &arg : gf->args()) {
    irb.CreateStore(&arg, alloca_ins);
    alloca_ins = alloca_ins->getNextNode();
  }
  ensure_branch(alloc_bb, bind_args_bb);
  return bind_args_bb;
}

// Returns block for binding arguments and binding return value
std::pair<BasicBlock*, BasicBlock*> create_bind_args_bb(LLVMContext &ctx, Function *gf, BasicBlock *prev_bb, BasicBlock *alloc_bb) {
  // Locate the call instruction, it should be the next last one otherwise something is wrong
  auto split_ins = cast<CallInst>(&*(++(prev_bb->rbegin())));
  auto bind_result_bb = prev_bb->splitBasicBlock(split_ins, Twine(alloc_bb->getName()).concat("-result"));
  auto call_ins = cast<CallInst>(bind_result_bb->begin());

  // Prepare the bind args bb
  auto bind_args_bb = BasicBlock::Create(ctx, Twine(alloc_bb->getName()).concat("-bind"), gf);
  IRBuilder<> irb(bind_args_bb);

  auto alloca_ins = &alloc_bb->front();
  for (auto &arg : call_ins->args()) {
    irb.CreateStore(&*arg, alloca_ins);
    alloca_ins = alloca_ins->getNextNode();
  }

  // If the return type is void, we just drop the call from the bind_resul_bb
  // Else we need to insert a load
  auto ret_ty = call_ins->getFunctionType()->getReturnType();
  if (!ret_ty->isVoidTy()) {
    IRBuilder<> irb(bind_result_bb);
    auto ld = irb.CreateLoad(ret_ty, alloca_ins);
    call_ins->replaceAllUsesWith(ld);
  }
  // There will be a branch left. Discard it. It will be updated when a return
  // instruction is encountered.
  call_ins->getNextNode()->removeFromParent();
  // Drop the call. If it returned any value, any use was replaced above.
  call_ins->removeFromParent();
  ensure_branch(prev_bb, alloc_bb);
  ensure_branch(alloc_bb, bind_args_bb);

  return {bind_args_bb, bind_result_bb};
}

BasicBlock *clone_block(LLVMContext &ctx, Function *gf, BasicBlock *prev_bb, BasicBlock *alloc_bb, BasicBlock *to_clone, callstack_ty &cs) {

  auto &state = cs.top();

  auto new_bb = BasicBlock::Create(ctx, to_clone->getParent()->getName(), gf);
  state.vm[to_clone] = new_bb; // TODO (hbrodin): Do we need this??
  for (auto &ins : *to_clone) {
    auto new_ins = ins.clone();
    state.vm[&ins] = new_ins;
    RemapInstruction(new_ins, state.vm,  RF_NoModuleLevelChanges);
    new_bb->getInstList().push_back(new_ins);
  }

  if (prev_bb)
    ensure_branch(prev_bb, new_bb);
  return new_bb;
}


// Stores whatever is normally returned from the function
// in the alloca block for the function, for later consumption
// by the call-replacement. If no return value, just skip store.
BasicBlock *handle_ret(BasicBlock *bb, callstack_ty& cs) {
  if (auto ret = dyn_cast<ReturnInst>(&bb->back())) {
    // This is a ret instruction, complete current function by joining the
    // load ret value and drop the ret instruction
    auto &state = cs.top();
    auto br = state.bind_ret_bb;
    auto alloca_bb = state.alloca_bb;
    
    cs.pop();
    if (br) {
      if (ret->getNumOperands() == 1) {
        IRBuilder<> irb(bb);
        irb.CreateStore(ret->getOperand(0), &*(++alloca_bb->rbegin()));
      }
      ret->removeFromParent();
      ensure_branch(bb, br);
      return br;
    }
  }
  return bb;
}

/*

Link a sequence of basic blocks representing exeuction

Each bb contains at most one call. A successor to a block with a call is either
part of the same function for uninstrumented calls (e.g. llvm.dbg.declare) or the
entry block of the new function. If it is an entry block the following split is done

Before: [caller-bb][callee-entry-bb]
After: [caller-bb/pre-call] [*arg-allocaa] [*arg-bind] [callee-entry-bb] ...[callee-ret] [caller-bb/postcall]
with * being newly created blocks to handle linking of function arguments/return value

arg-alloca: Allocas for all function arguments and return value
arg-bind: extract function operands and store them in corresponding arg-alloca
callee-ret: replace the ret instruction with a store of the return value into arg-alloca
caller-bb/postcall: replace the call with a load from arg-alloca (return value)

*/
void create_gigafunction_direct(LLVMContext &ctx, Module &mod, char const *fname, blockindex_t const &bi) {

  //auto void_ty = Type::getVoidTy(ctx);
  //auto gigafunction_ty = FunctionType::get(void_ty, {}, false);
  //auto gf = Function::Create(gigafunction_ty, llvm::Function::ExternalLinkage, "gigafunction", mod);
  Function *gf{nullptr};

  trace_reader tr(fname);
  callstack_ty callstack;


  BasicBlock *prev_bb{nullptr};
  for (auto e = tr.next();e;e=tr.next()) {
    auto [tid, bid] = e.value();
    auto it = bi.find(bid);

    if (it == bi.end()) {
      errs() << "Broken analysis. Failed to find block " << bid << " in the block index. Abort.\n";
      abort();
    }

    auto bb = it->second;

    // This is the initial block for a function. Prepare blocks for argument/return value store
    if (bb->isEntryBlock()) {
      if (!gf) {
         gf = Function::Create(bb->getParent()->getFunctionType(), llvm::Function::ExternalLinkage, "gigafunction", mod);
      }


      // Allocate storage for arguments/return values
      callstack.emplace(nullptr);
      auto alloc_bb = create_func_args_block(ctx, gf, bb->getParent(), prev_bb, callstack);
      callstack.top().alloca_bb = alloc_bb;
      if (prev_bb) {
        // Store parameters to alloc_bb
        auto [bind_args_bb, bind_results_bb] = create_bind_args_bb(ctx, gf, prev_bb, alloc_bb);
        callstack.top().bind_ret_bb = bind_results_bb;

        prev_bb = bind_args_bb;
      } else {
        auto bind_args_bb = create_top_bind_args_bb(ctx, gf, alloc_bb);
        prev_bb = bind_args_bb;
      }
    }
    // Clone block and chain to prev block
    prev_bb = clone_block(ctx, gf, prev_bb, callstack.top().alloca_bb, bb, callstack);

    // Check if we just hit a ret-block
    prev_bb = handle_ret(prev_bb, callstack);

  }
  gf->print(outs());
}

blockindex_t build_block_index(Module &m) {
  gigafunction::blockindex_t blockindex;
  for (auto& f : m) {
    for (auto& bb : f) {
      blockindex.emplace(gigafunction::read_block_id(bb)->getZExtValue(), &bb);
    }
  }
  return blockindex;
}

}

int main(int argc, char *argv[]) {


  SMDiagnostic error;
  LLVMContext ctx;
  auto mod = parseIRFile(argv[1], error, ctx);
  outs() << "Loaded module " << mod.get() << "\n";

  auto blockindex = gigafunction::build_block_index(*mod);


  gigafunction::create_gigafunction_direct(ctx, *mod, argv[2], blockindex);
  

  return 0;

}