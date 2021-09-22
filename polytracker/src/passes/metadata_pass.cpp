#include "polytracker/metadata_pass.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Metadata.h"
#include <iostream>
#include <string>
using namespace llvm;

/*
This LLVM pass creates logistical information needed for tracing.

This pass is supposed to be run after the BB splitting pass.

1. Creates unique identifiers for functions and basic blocks
2. Stores it in a global map within the LLVM bitcode file
3. Tags the object (function, block, etc) with metadata corresponding to it's ID

These unique id's are uint64_t's. The first 4 bytes represent the function_id,
the last 4 bytes the block_id. It looks like this. 0000 0000
          |____|____|
           func blck

Functions have a unique idea, but block ids are related to specific functions.

We don't have unique ID's for instructions, the BBSplitting pass helps us with
this. That pass guarantees that every basic block ends in a control flow
instruction, a jump, a call, etc. There will be no continuations back into the
caller block. This means based on block information, we know exactly what
instructions are executed.

Storing the mapping at compile time removes the need to pass around
strings/store function names/block locations at runtime.
*/

namespace polymeta {

static llvm::Constant *create_str(llvm::Module &mod, std::string &str) {
  auto arr_ty = llvm::ArrayType::get(
      llvm::IntegerType::getInt8Ty(mod.getContext()), str.size() + 1);

  auto int8_ty = llvm::IntegerType::getInt8Ty(mod.getContext());

  // TODO (Carson) this feels hacky
  std::vector<llvm::Constant *> vals;
  for (auto i = 0; i < str.size(); i++) {
    auto new_const = llvm::ConstantInt::get(int8_ty, str[i]);
    vals.push_back(new_const);
  }

  auto int8ptr_ty = llvm::IntegerType::getInt8PtrTy(mod.getContext());
  auto init = llvm::ConstantArray::get(arr_ty, vals);
  // Not int8_ptr, arr_ty
  auto str_global = new llvm::GlobalVariable(
      mod, init->getType(), true, llvm::GlobalVariable::InternalLinkage, init);

  auto casted = llvm::ConstantExpr::getPointerCast(str_global, int8ptr_ty);
  return casted;
}

// Map functions to ids
static llvm::Constant *
create_func_mapping(llvm::Module &mod,
                    std::unordered_map<std::string, uint32_t> &func_index_map) {
  llvm::LLVMContext &context = mod.getContext();
  auto int64_type = llvm::IntegerType::getInt64Ty(mod.getContext());
  auto int32_type = llvm::IntegerType::getInt32Ty(mod.getContext());
  auto int8_ty = llvm::IntegerType::getInt8Ty(context);
  auto str_type = llvm::IntegerType::getInt8PtrTy(mod.getContext());

  // func names and func_ids
  llvm::StructType *func_struct = llvm::StructType::create(
      mod.getContext(), {str_type, int32_type}, "func_struct");

  // Convert map to func_struct types
  std::vector<llvm::Constant *> const_structs;
  for (auto pair : func_index_map) {
    auto key = pair.first;
    auto val = pair.second;
    auto key_const = create_str(mod, key);
    auto val_const = llvm::ConstantInt::get(
        llvm::IntegerType::getInt32Ty(mod.getContext()), val);
    auto struct_const =
        llvm::ConstantStruct::get(func_struct, {key_const, val_const});
    const_structs.push_back(struct_const);
  }
  // Create it as a fixed array type and insert it into the module as a global
  auto arr_type = llvm::ArrayType::get(func_struct, const_structs.size());
  auto global_structs = new llvm::GlobalVariable(
      mod, arr_type, true, llvm::GlobalVariable::InternalLinkage,
      llvm::ConstantArray::get(arr_type, const_structs), "func_index_map");

  return global_structs;
}

bool MetadataPass::runOnModule(Module &mod) {

  LLVMContext &context = mod.getContext();
  uint64_t inst_num = 0;
  for (auto &func : mod) {
    for (auto &block : func) {
      for (auto &inst : block) {
        // TODO (Carson) encode just as integer metadata later probably
        auto str_val = std::to_string(inst_num++);
        llvm::MDNode *node =
            llvm::MDNode::get(context, llvm::MDString::get(context, str_val));
        inst.setMetadata("__poly_inst_num", node);
      }
    }
  }

  return false;
}
char MetadataPass::ID = 0;
} // namespace polymeta
static llvm::RegisterPass<polymeta::MetadataPass>
    X("meta", "Adds runtime monitoring calls to polytracker runtime",
      false /* Only looks at CFG */, false /* Analysis Pass */);