#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Mangler.h>
#include <llvm/Support/FileSystem.h>

#include <fstream>

#include "gigafunction/pass/detour_taint_functions.h"

using namespace llvm;

namespace gigafunction {
auto detour_filename = "detour.txt";

DetourTaintFunctionsPass::DetourTaintFunctionsPass() {
  std::ifstream ifs(detour_filename, std::ios::in);
  for (std::string line; std::getline(ifs, line);) {
    function_names.insert(std::move(line));
  }
}

namespace {
// https://llvm.org/doxygen/Mangler_8cpp_source.html#l00033
StringRef dropManglerPrefix(StringRef name) {
  if (name[0] == '\01') {
    return name.substr(1);
  }
  return name;
}

SmallString<16> detouredFunctionName(StringRef original) {
  return {"gigafunction_", original};
}
} // namespace

llvm::PreservedAnalyses
DetourTaintFunctionsPass::run(llvm::Function &f,
                              llvm::FunctionAnalysisManager & /*AM*/) {
  /*
  TODO: From PolyTracker src
   if (auto function = call->getCalledFunction()) {
      if (function->hasName()) {
        fname = function->getName().data();
      }
      // Note (Carson): Changed getCalledValue() --> Operand()
      // https://reviews.llvm.org/D78882
    } else if (auto v = call->getCalledOperand()->stripPointerCasts()) {
      if (v->hasName()) {
        fname = v->getName().data();
      }
    }
    */
  bool changes = false;
  auto mod = f.getParent();
  for (auto &bb : f) {
    for (auto &ins : bb) {
      if (auto call = dyn_cast<CallInst>(&ins)) {
        if (auto cf = call->getCalledFunction()) {
          // Direct call, if indirect this returns null. Try to cover that via
          // the StoreInst rewrite.
          auto name = dropManglerPrefix(cf->getName());
          if (function_names.contains(name)) {
            auto fn = mod->getOrInsertFunction(detouredFunctionName(name),
                                               cf->getFunctionType());
            call->setCalledFunction(fn);
            changes = true;
          }
        }
        // If call target name is in list of replacements
        // combine name with gigafunction_... replace target
      } else if (auto store = dyn_cast<StoreInst>(&ins)) {
        // If source is address of a function we are interested in...
      }
    }
  }

  return changes ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace gigafunction