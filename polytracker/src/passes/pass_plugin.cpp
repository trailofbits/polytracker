/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include "polytracker/passes/DataFlowSanitizer.h"
#include "polytracker/passes/remove_fn_attr.h"
#include "polytracker/passes/taint_tracking.h"
#include "polytracker/passes/tainted_control_flow.h"

llvm::PassPluginLibraryInfo getPolyTrackerPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "PolyTracker", "",
          [](llvm::PassBuilder &pb) {
            pb.registerPipelineParsingCallback(
                [](llvm::StringRef name, llvm::ModulePassManager &mpm,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (name == "pt-dfsan") {
                    mpm.addPass(polytracker::DataFlowSanitizerPass());
                    return true;
                  }
                  if (name == "pt-taint") {
                    mpm.addPass(polytracker::TaintTrackingPass());
                    return true;
                  }
                  if (name == "pt-rm-fn-attr") {
                    mpm.addPass(polytracker::RemoveFnAttrsPass());
                    return true;
                  }
                  if (name == "pt-tcf") {
                    mpm.addPass(polytracker::TaintedControlFlowPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getPolyTrackerPluginInfo();
}