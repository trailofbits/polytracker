#ifndef BB_TRACK_PASS
#define BB_TRACK_PASS
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Pass.h"
#include <unordered_map>
#include <vector>

namespace bbtrack {
struct BBTrack : public llvm::ModulePass {
  static char ID;
  BBTrack() : ModulePass(ID) {}
  bool runOnModule(llvm::Module &module) override;
  bool analyzeFunction(llvm::Function *f);
  bool analyzeBlock(llvm::Function *func, llvm::BasicBlock *curr_bb,
                    const uint64_t &bb_index,
                    std::vector<llvm::BasicBlock *> &split_bbs,
                    llvm::DominatorTree &DT);

  void initializeTypes(llvm::Module &mod);

  llvm::FunctionCallee block_entry_log;
  llvm::FunctionCallee track_start;
  llvm::Value *stack_loc;
  llvm::Module *mod;
  std::unordered_map<llvm::BasicBlock *, uint64_t> block_global_map;
  std::unordered_map<uint64_t, uint8_t> block_type_map;
};

}; // namespace bbtrack

#endif // BB_TRACK_PASS