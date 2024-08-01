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

/*
void Parser::ConsumePermittedUnrealTokens(PermittedUnrealTokens Tokens) {
  auto TokAllowed = [this, Tokens]() {
    if (Tokens == PermittedUnrealTokens::PUT_USpecifiers) {
      return Tok.isOneOf(tok::annot_unreal_uclass, tok::annot_unreal_uinterface,
                         tok::annot_unreal_ustruct, tok::annot_unreal_ufunction,
                         tok::annot_unreal_uproperty,
                         tok::annot_unreal_specifier,
                         tok::annot_unreal_metadata_specifier);
    } else if (Tokens == PermittedUnrealTokens::PUT_ApiExport) {
      return Tok.getKind() == tok::annot_unreal_exported;
    }
    return false;
  };
  while (TokAllowed()) {
    if (Tok.getAnnotationValue() == nullptr) {
      HandlePragmaUnreal(Tok.getKind(), UnrealSpecifier());
    } else {
      HandlePragmaUnreal(Tok.getKind(),
                         *(UnrealSpecifier *)Tok.getAnnotationValue());
    }
  }
  if (Tok.isOneOf(tok::annot_unreal_uclass, tok::annot_unreal_uinterface,
                  tok::annot_unreal_ustruct, tok::annot_unreal_ufunction,
                  tok::annot_unreal_uproperty, tok::annot_unreal_specifier,
                  tok::annot_unreal_metadata_specifier,
                  tok::annot_unreal_exported)) {
    Diag(Tok.getLocation(),
         diag::err_unreal_annotation_found_in_unexpected_place)
        << SourceRange();
    assert(false /* Unreal Engine annotation found in unexpected place *);
  }
}
*/

/*
void Parser::HandlePragmaUnreal(tok::TokenKind Kind,
                                const UnrealSpecifier &UnrealData) {
  ConsumeAnnotationToken();
}
*/