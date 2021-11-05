
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <algorithm>
#include <deque>
#include <unordered_map>

#include "gigafunction/pass/mark_basic_blocks.h"
#include "gigafunction/traceio/trace_reader.h"
#include "gigafunction/types.h"

using namespace llvm;

namespace gigafunction {
using blockindex_t = std::unordered_map<block_id, BasicBlock *>;

// TODO (hbrodin): This was stolen from instrument_basic_blocks.cpp create lib.
ConstantInt *read_block_id(BasicBlock &bb) {
  if (MDNode *n = bb.front().getMetadata(gigafunction::get_metadata_tag())) {
    auto n0 = cast<ConstantAsMetadata>(n->getOperand(0))->getValue();
    return cast<ConstantInt>(n0);
  }
  errs() << "Warning did not find metadata tag '"
         << gigafunction::get_metadata_tag() << "' for block in function "
         << bb.getParent()->getName() << "\n"
         << " ensure the markbasicblocks-pass have been run previously.";
  return nullptr;
}

// Create a branch from->to. If last instr in from is a branch of any kind
// update it to to
void ensure_branch(BasicBlock *from, BasicBlock *to) {
  if (auto branch = dyn_cast<BranchInst>(&from->getInstList().back())) {
    if (branch->isUnconditional()) {
      branch->setOperand(0, to);
      return; // Early abort, just change branch target
    }
    // drop conditional branch
    branch->eraseFromParent();
  }

  // insert branch
  IRBuilder<> irb(from);
  irb.CreateBr(to);
}

struct frame_state {
  CallInst *caller{};
  Value *replace_Call{};
  // Calls in the current frame
  SmallVector<CallInst *> calls;
  SmallVector<std::pair<CallInst *, Value *>> replace_calls;

  // Remapping of values in current frame
  ValueToValueMapTy vm;

  frame_state() {}
  frame_state(CallInst *caller) : caller(caller) {}
};

using call_frames = std::deque<frame_state>;

struct gigafunction_state {
  call_frames frames;
  Function *gigafunction{nullptr};
  BasicBlock *prev_translated_bb{nullptr};
};

void on_entry_block(BasicBlock *orig_bb, gigafunction_state &state) {
  if (state.frames.empty()) {
    auto orig_func = orig_bb->getParent();
    state.gigafunction = Function::Create(
        orig_func->getFunctionType(), llvm::Function::ExternalLinkage,
        "gigafunction", orig_func->getParent());

    // Initialize empty frame
    auto &frame = state.frames.emplace_back();

    // Map any references to orginal function arguments to our new gigafunction
    // args
    auto gf = state.gigafunction;
    auto f = orig_bb->getParent();
    for (auto gf_arg = gf->arg_begin(), f_arg = f->arg_begin();
         gf_arg != gf->arg_end(); gf_arg++, f_arg++) {
      frame.vm[f_arg] = gf_arg;
    }
  } else {
    assert(state.prev_translated_bb && "BUG: Inconsistent state. Should have "
                                       "prev_translated_bb when !cf.empty()");
    auto caller = cast<CallInst>(
        &*(++(state.prev_translated_bb->rbegin()))); // Bug if not a call here

    // append this call to parent frame calls to be removed
    state.frames.back().calls.emplace_back(caller);

    // Create a new frame originating from caller
    auto &frame = state.frames.emplace_back(caller);

    // Map all orig_bb arguments to caller operands
    auto f = orig_bb->getParent();
    auto c_arg = caller->arg_begin();
    for (auto &arg : f->args()) {
      assert(c_arg->getOperandNo() == arg.getArgNo());
      frame.vm[&arg] = cast<Value>(c_arg);
      ++c_arg;
    }
  }
}

void on_ret_block(ReturnInst *ret, gigafunction_state &state) {
  // Have parent frame, update caller to be replaced by operand 0 of the ret,
  // if any
  auto &current_frame = state.frames.back();

  // Replace any usage of calls in the current frame with their "inlined
  // versions" finally drop the calls
  for (auto [call, replace] : current_frame.replace_calls) {
    if (replace)
      call->replaceAllUsesWith(replace);
    call->eraseFromParent();
  }

  if (state.frames.size() > 1) {
    auto caller = current_frame.caller;
    assert(caller && "BUG: Should be a caller if there is a parent frame");

    auto &parent_frame = *(++state.frames.rbegin());
    if (ret->getNumOperands() == 1) {
      parent_frame.replace_calls.emplace_back(caller, ret->getOperand(0));
    } else {
      parent_frame.replace_calls.emplace_back(caller, nullptr);
    }

    // Drop the ret, it will be replaced by a branch later on
    ret->eraseFromParent();
  }

  state.frames.pop_back();
}

BasicBlock *clone_single_bb(BasicBlock *orig_bb, gigafunction_state &state) {

  auto &current_frame = state.frames.back();

  auto translated_bb =
      BasicBlock::Create(state.gigafunction->getContext(),
                         orig_bb->getParent()->getName(), state.gigafunction);
  current_frame.vm[orig_bb] =
      translated_bb; // TODO (hbrodin): Do we need this??
  for (auto &ins : *orig_bb) {
    auto new_ins = ins.clone();
    current_frame.vm[&ins] = new_ins;
    RemapInstruction(new_ins, current_frame.vm, RF_NoModuleLevelChanges);
    translated_bb->getInstList().push_back(new_ins);
  }

  if (state.prev_translated_bb)
    ensure_branch(state.prev_translated_bb, translated_bb);
  return translated_bb;
}

// Constructs gigafunctions given a blockindex
// A blockindex is constructed by running a binary instrumented to emit a
// block-id for each basic block From each block-id, a chain of basic blocks is
// copied into a 'gigafunction'. Special handling of function arguments is
// needed. Need to replace users of call instructions with the value from ret of
// the called function and also make sure that the operands to the call
// instruction is bound to the basic blocks representing the callee.
void create_gigafunctions(LLVMContext &ctx, Module &mod, char const *fname,
                          blockindex_t const &bi) {
  trace_reader tr(fname);
  gigafunction_state state;

  for (auto e = tr.next(); e; e = tr.next()) {
    auto [tid, bid] = e.value();
    auto it = bi.find(bid);

    if (it == bi.end()) {
      errs() << "Broken analysis. Failed to find block " << bid
             << " in the block index. Abort.\n";
      abort();
    }

    auto orig_bb = it->second;
    if (orig_bb->isEntryBlock()) {
      on_entry_block(orig_bb, state);
    }

    auto translated_bb = clone_single_bb(orig_bb, state);
    if (auto ret = dyn_cast<ReturnInst>(&*translated_bb->rbegin())) {
      on_ret_block(ret, state);
    }

    if (state.prev_translated_bb) {
      ensure_branch(state.prev_translated_bb, translated_bb);
    }

    state.prev_translated_bb = translated_bb;
  }

  verifyFunction(*state.gigafunction, &outs());
}

blockindex_t build_block_index(Module &m) {
  gigafunction::blockindex_t blockindex;
  for (auto &f : m) {
    for (auto &bb : f) {
      blockindex.emplace(gigafunction::read_block_id(bb)->getZExtValue(), &bb);
    }
  }
  return blockindex;
}

} // namespace gigafunction

int main(int argc, char *argv[]) {

  SMDiagnostic error;
  LLVMContext ctx;
  auto mod = parseIRFile(argv[1], error, ctx);
  if (!mod) {
    errs() << "Failed to load module from " << argv[1] << "\n";
    return 1;
  }
  outs() << "Loaded module " << mod.get() << "\n";

  auto blockindex = gigafunction::build_block_index(*mod);

  gigafunction::create_gigafunctions(ctx, *mod, argv[2], blockindex);

  if (argc == 4) {
    std::error_code ec;
    raw_fd_ostream os(argv[3], ec, sys::fs::CD_CreateAlways);
    if (ec) {
      errs() << ec.message() << "\n";
    }
    WriteBitcodeToFile(*mod, os);
    outs() << "Gigafunction module written to " << argv[3] << "\n";
  }

  return 0;
}