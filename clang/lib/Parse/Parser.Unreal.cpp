#include "clang/Parse/Parser.h"

using namespace clang;

void Parser::PPLexWithUnrealAnnotationTokens() {
  PP.Lex(Tok);
  while (Tok.isOneOf(
    tok::annot_unreal_uclass, tok::annot_unreal_uinterface,
    tok::annot_unreal_ustruct, tok::annot_unreal_ufunction,
    tok::annot_unreal_uproperty, tok::annot_unreal_specifier,
    tok::annot_unreal_metadata_specifier,
    tok::annot_unreal_exported)) [[unlikely]] {
    if (Tok.getAnnotationValue() == nullptr) {
      Actions.ActOnUnrealData(
        Tok.getLocation(), 
        Tok.getKind(), 
        UnrealSpecifier());
    } else {
      Actions.ActOnUnrealData(
        Tok.getLocation(), 
        Tok.getKind(), 
        *(UnrealSpecifier *)Tok.getAnnotationValue());
    }
    PP.Lex(Tok);
  }
}