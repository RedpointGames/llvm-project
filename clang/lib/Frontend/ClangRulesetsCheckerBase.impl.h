#pragma once

#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"

namespace clang::rulesets {

struct ClangRulesetsCheckerDiagnostic {
public:
  ClangRulesetsCheckerDiagnostic(
    const clang::SourceLocation& InLocation,
    bool InIsNote,
    llvm::StringRef InMessage)
    : Location(InLocation)
    , IsNote(InIsNote)
    , Message(InMessage)
  {
  }

  clang::SourceLocation Location;
  bool IsNote;
  llvm::StringRef Message;
};

using ClangRulesetsCheckerReportDiagnostics = std::function<void(
      const std::vector<ClangRulesetsCheckerDiagnostic>& Diagnostics)>;

class ClangRulesetsCheckerBase {
public:
  virtual ~ClangRulesetsCheckerBase() = default;

  virtual std::string getName() const = 0;

  virtual void registerMatcherWithFinder(clang::ast_matchers::MatchFinder& Finder, clang::ast_matchers::MatchFinder::MatchCallback *Action) const = 0;

  virtual void processMatchResult(
    ASTContext &AST, 
    const clang::ast_matchers::MatchFinder::MatchResult &Result,
    const ClangRulesetsCheckerReportDiagnostics& ReportDiagnostics) const = 0;
};

} // namespace clang::rulesets
