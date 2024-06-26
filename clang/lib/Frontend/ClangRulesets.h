#pragma once

#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"

namespace clang::rulesets {

class ClangRulesetsProvider {
public:
  static void CreateAndAddASTConsumers(
      clang::CompilerInstance &CI,
      std::vector<std::unique_ptr<ASTConsumer>> &BeforeConsumers,
      std::vector<std::unique_ptr<ASTConsumer>> &AfterConsumers);
};

} // namespace clang::rulesets
