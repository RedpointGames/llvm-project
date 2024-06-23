// Copyright June Rhodes. Apache License v2.0 with LLVM Exceptions.

// @unreal: BEGIN
#ifndef LLVM_CLANG_UNREAL_ENGINE_PP_TAGGER_H
#define LLVM_CLANG_UNREAL_ENGINE_PP_TAGGER_H

#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/UnrealEngineData.h"

namespace clang {

class UnrealEnginePPTagger : public PPCallbacks {
  Preprocessor &PP;
  SourceManager *SM;
  std::vector<UnrealSpecifier *> AllocatedStrings;

  void *AllocSpecifier(const std::string &InSpecifierName,
                       const std::string &InSpecifierValue);

public:
  UnrealEnginePPTagger(Preprocessor &PP, SourceManager *SM);
  ~UnrealEnginePPTagger();

  virtual void MacroExpands(const Token &MacroNameTok,
                            const MacroDefinition &MD, SourceRange Range,
                            const MacroArgs *Args) override;
};

}; // namespace clang

#endif
// @unreal: END