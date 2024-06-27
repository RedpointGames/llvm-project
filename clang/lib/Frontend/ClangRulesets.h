#pragma once

#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"

namespace clang::rulesets {

class ClangRulesetsProvider {
public:
  static std::unique_ptr<ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &CI);
};

} // namespace clang::rulesets
