
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

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


void dump_block_trace(char const *fname, blockindex_t const &bi) {
  trace_reader tr(fname);
  for (auto e = tr.next();e;e=tr.next()) {
    auto bid = e.value().bid;
    auto it = bi.find(bid);
    if (it == bi.end())
      errs() << "Failed to find bid: " << bid << "\n";
    else
      outs() << "Thread: " << e.value().tid << " blockid: " << bid << " in function: " << it->second->getParent()->getName() << "\n";
  }
}

}

int main(int argc, char *argv[]) {


  SMDiagnostic error;
  LLVMContext ctx;
  auto mod = parseIRFile(argv[1], error, ctx);
  outs() << "Loaded module " << mod.get() << "\n";

  gigafunction::blockindex_t blockindex;

  for (auto& f : *mod) {
    for (auto& bb : f) {
      blockindex.emplace(gigafunction::read_block_id(bb)->getZExtValue(), &bb);
    }
  }


  for (auto& e : blockindex) {
    outs() << "BlockID: " << e.first << " in function: " << e.second->getParent()->getName() << "\n";
  }

  gigafunction::dump_block_trace(argv[2], blockindex);

  

  return 0;

}