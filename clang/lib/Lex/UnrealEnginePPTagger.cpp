// Copyright June Rhodes. Apache License v2.0 with LLVM Exceptions.

// @unreal: BEGIN
#include "clang/Lex/UnrealEnginePPTagger.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Lex/MacroArgs.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/Token.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;

UnrealEnginePPTagger::UnrealEnginePPTagger(Preprocessor &PP, SourceManager *SM)
    : PP(PP), SM(SM){};

UnrealEnginePPTagger::~UnrealEnginePPTagger() {

  for (const auto &Str : this->AllocatedStrings) {
    delete Str;
  }
  this->AllocatedStrings.clear();
}

void *
UnrealEnginePPTagger::AllocSpecifier(const std::string &InSpecifierName,
                                     const std::string &InSpecifierValue) {
  UnrealSpecifier *Ptr = new UnrealSpecifier();
  Ptr->SpecifierName = InSpecifierName;
  Ptr->SpecifierValue = InSpecifierValue;
  this->AllocatedStrings.push_back(Ptr);
  return (void *)Ptr;
}

inline bool iequals(const llvm::StringRef &a, const std::string &b) {
  unsigned int sz = a.size();
  if (b.size() != sz)
    return false;
  for (unsigned int i = 0; i < sz; ++i)
    if (tolower(a[i]) != tolower(b[i]))
      return false;
  return true;
}

struct TokenInfo {
  tok::TokenKind Kind;
  void *Data;
  TokenInfo(tok::TokenKind InKind, void *InData) : Kind(InKind), Data(InData){};
};

void UnrealEnginePPTagger::MacroExpands(const Token &MacroNameTok,
                                        const MacroDefinition &MD,
                                        SourceRange Range,
                                        const MacroArgs *Args) {
  if (this->PP.isParsingIfOrElifDirective()) {
    return;
  }
  if (MacroNameTok.isAnyIdentifier()) {
    llvm::StringRef MacroName = MacroNameTok.getIdentifierInfo()->getName();
    bool RequiresParameterHandling = false;
    std::vector<TokenInfo> TokensToPush;
    if (MacroName == "UCLASS") {
      TokensToPush.push_back(
          TokenInfo(tok::TokenKind::annot_unreal_uclass, nullptr));
      RequiresParameterHandling = true;
    } else if (MacroName == "USTRUCT") {
      TokensToPush.push_back(
          TokenInfo(tok::TokenKind::annot_unreal_ustruct, nullptr));
      RequiresParameterHandling = true;
    } else if (MacroName == "UINTERFACE") {
      TokensToPush.push_back(
          TokenInfo(tok::TokenKind::annot_unreal_uinterface, nullptr));
      RequiresParameterHandling = true;
    } else if (MacroName == "UPROPERTY") {
      TokensToPush.push_back(
          TokenInfo(tok::TokenKind::annot_unreal_uproperty, nullptr));
      RequiresParameterHandling = true;
    } else if (MacroName == "UFUNCTION") {
      TokensToPush.push_back(
          TokenInfo(tok::TokenKind::annot_unreal_ufunction, nullptr));
      RequiresParameterHandling = true;
    } else if (Args == nullptr && MacroName.ends_with("_API")) {
      /*static long count = 0;
      llvm::errs() << count++ << ": " << MacroName << "\n";
        TokensToPush.push_back(
            TokenInfo(tok::TokenKind::annot_unreal_exported, nullptr));*/
    }
    if (RequiresParameterHandling && Args != nullptr) {
      assert(Args->getNumMacroArguments() == 1 &&
             "Expected U* specifier to only have one (varargs) argument");
      const Token *ArgTokens = Args->getUnexpArgument(0);
      std::string CurrentIdentifier = "";
      unsigned int i = 0;
      unsigned int ArgsLength = Args->getArgLength(ArgTokens);
#define CONSUME_PP_TOKEN() (ArgTokens[i++])
#define SKIP_PP_TOKEN() i += 1
#define PEEK_PP_TOKEN() (ArgTokens[i])
#define IS_LAST() (i >= ArgsLength)
#define STRICT_MODE 1
#if defined(STRICT_MODE)
#define MALFORMED()                                                            \
  assert(false && "Malformed");                                                \
  Malformed = true;                                                            \
  break;
#else
#define MALFORMED()                                                            \
  Malformed = true;                                                            \
  break;
#endif
      bool Malformed = false;
      while (i < ArgsLength && !Malformed) {
        // Consume token.
        const Token &Tok = CONSUME_PP_TOKEN();
        std::string SpecifierName;
        if (Tok.getKind() == tok::TokenKind::identifier) {
          SpecifierName = Tok.getIdentifierInfo()->getName().str();
        } else if (Tok.getKind() == tok::TokenKind::kw_const) {
          SpecifierName = "const";
        } else {
          MALFORMED();
        }
        if (IS_LAST() || PEEK_PP_TOKEN().getKind() == tok::TokenKind::comma) {
          // This is the last standalone specifier.
          TokensToPush.push_back(
              TokenInfo(tok::TokenKind::annot_unreal_specifier,
                        this->AllocSpecifier(SpecifierName, "")));
          if (IS_LAST()) {
            // No more arguments.
            break;
          } else {
            // Just skip the current comma, and continue to
            // process the next specifier.
            SKIP_PP_TOKEN();
            continue;
          }
        }
        // We have more tokens and the current token is not a comma.
        // If it's not an equals sign, this is malformed.
        if (PEEK_PP_TOKEN().getKind() != tok::TokenKind::equal) {
          MALFORMED();
        }
        SKIP_PP_TOKEN(); // Skip the equal sign.
        if (IS_LAST()) {
          MALFORMED();
        }
        bool IsNegative = false;
        if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::minus) {
          IsNegative = true;
          CONSUME_PP_TOKEN();
        }
        if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::identifier) {
          // Value is an identifier, like a function name.
          TokensToPush.push_back(TokenInfo(
              tok::TokenKind::annot_unreal_specifier,
              this->AllocSpecifier(
                  SpecifierName,
                  PEEK_PP_TOKEN().getIdentifierInfo()->getName().str())));
          SKIP_PP_TOKEN(); // We used the token.
        } else if (PEEK_PP_TOKEN().getKind() ==
                       tok::TokenKind::string_literal ||
                   PEEK_PP_TOKEN().getKind() ==
                       tok::TokenKind::numeric_constant) {
          // Value is a string or numeric literal.
          TokensToPush.push_back(TokenInfo(
              tok::TokenKind::annot_unreal_specifier,
              this->AllocSpecifier(
                  SpecifierName, (IsNegative ? "-" : "") +
                                     StringRef(PEEK_PP_TOKEN().getLiteralData(),
                                               PEEK_PP_TOKEN().getLength())
                                         .str())));
          SKIP_PP_TOKEN(); // We used the token.
        } else if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::kw_true ||
                   PEEK_PP_TOKEN().getKind() == tok::TokenKind::kw_false) {
          // Value is a boolean.
          TokensToPush.push_back(
              TokenInfo(tok::TokenKind::annot_unreal_specifier,
                        this->AllocSpecifier(SpecifierName,
                                             PEEK_PP_TOKEN().getKind() ==
                                                     tok::TokenKind::kw_true
                                                 ? "true"
                                                 : "false")));
          SKIP_PP_TOKEN(); // We used the token.
        } else if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::l_paren) {
          bool AddAsMetadata = false;
          // We only support meta lists at the moment; all other lists are
          // simply added without a value. However, for those other lists, we
          // still need to parse them.
          if (iequals(SpecifierName, "meta")) {
            AddAsMetadata = true;
          } else {
            TokensToPush.push_back(
                TokenInfo(tok::TokenKind::annot_unreal_specifier,
                          this->AllocSpecifier(SpecifierName, "")));
          }
          SKIP_PP_TOKEN(); // Skip the left paren.
          while (i < ArgsLength && !Malformed) {
            // Consume token.
            const Token &Tok = CONSUME_PP_TOKEN();
            llvm::StringRef MetadataName;
            if (Tok.getKind() == tok::TokenKind::identifier) {
              MetadataName = Tok.getIdentifierInfo()->getName();
            } else if (Tok.getKind() == tok::TokenKind::string_literal) {
              // Doesn't happen for metadata, but can happen for other kinds of
              // lists that we currently discard.
              MetadataName = StringRef(Tok.getLiteralData(), Tok.getLength());
            } else {
              // Invalid formed specifier list.
              MALFORMED();
            }
            if (IS_LAST() ||
                PEEK_PP_TOKEN().getKind() == tok::TokenKind::comma ||
                PEEK_PP_TOKEN().getKind() == tok::TokenKind::r_paren) {
              // This is the last standalone specifier.
              if (AddAsMetadata) {
                TokensToPush.push_back(
                    TokenInfo(tok::TokenKind::annot_unreal_metadata_specifier,
                              this->AllocSpecifier(MetadataName.str(), "")));
              }
              if (IS_LAST()) {
                // No more arguments.
                break;
              } else if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::r_paren) {
                // Consume the right paren, and break so we go back to
                // processing specifiers.
                SKIP_PP_TOKEN();
                break;
              } else {
                // Just skip the current comma, and continue to
                // process the next metadata.
                SKIP_PP_TOKEN();
                continue;
              }
            }
            // We have more tokens and the current token is not a comma.
            // If it's not an equals sign, this is malformed.
            if (PEEK_PP_TOKEN().getKind() != tok::TokenKind::equal) {
              MALFORMED();
            }
            SKIP_PP_TOKEN(); // Skip the equal sign.
            if (IS_LAST()) {
              MALFORMED();
            }
            bool IsNegative = false;
            if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::minus) {
              IsNegative = true;
              CONSUME_PP_TOKEN();
            }
            if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::identifier) {
              // Value is an identifier, like a function name.
              if (AddAsMetadata) {
                TokensToPush.push_back(TokenInfo(
                    tok::TokenKind::annot_unreal_metadata_specifier,
                    this->AllocSpecifier(
                        MetadataName.str(),
                        PEEK_PP_TOKEN().getIdentifierInfo()->getName().str())));
              }
              SKIP_PP_TOKEN(); // We used the token.
            } else if (PEEK_PP_TOKEN().getKind() ==
                           tok::TokenKind::string_literal ||
                       PEEK_PP_TOKEN().getKind() ==
                           tok::TokenKind::numeric_constant) {
              // Value is a string or numeric literal.
              if (AddAsMetadata) {
                TokensToPush.push_back(TokenInfo(
                    tok::TokenKind::annot_unreal_metadata_specifier,
                    this->AllocSpecifier(
                        MetadataName.str(),
                        (IsNegative ? "-" : "") +
                            StringRef(PEEK_PP_TOKEN().getLiteralData(),
                                      PEEK_PP_TOKEN().getLength())
                                .str())));
              }
              SKIP_PP_TOKEN(); // We used the token.
            } else if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::kw_true ||
                       PEEK_PP_TOKEN().getKind() == tok::TokenKind::kw_false) {
              // Value is a boolean.
              if (AddAsMetadata) {
                TokensToPush.push_back(TokenInfo(
                    tok::TokenKind::annot_unreal_metadata_specifier,
                    this->AllocSpecifier(MetadataName.str(),
                                         PEEK_PP_TOKEN().getKind() ==
                                                 tok::TokenKind::kw_true
                                             ? "true"
                                             : "false")));
              }
              SKIP_PP_TOKEN(); // We used the token.
            } else {
              MALFORMED();
            }
            if (!IS_LAST()) {
              if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::comma) {
                SKIP_PP_TOKEN(); // Skip the comma.
              } else if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::r_paren) {
                // Consume the right paren, and break so we go back to
                // processing specifiers.
                SKIP_PP_TOKEN();
                break;
              } else {
                MALFORMED();
              }
            }
          }
          if (Malformed) {
            break;
          }
        }
        if (!IS_LAST()) {
          if (PEEK_PP_TOKEN().getKind() == tok::TokenKind::comma) {
            SKIP_PP_TOKEN(); // Skip the comma.
          } else {
            MALFORMED();
          }
        }
      }
    }

    // Now push the tokens into the stream. Due to the way EnterAnnotationToken
    // works, we have to push them in *REVERSE ORDER*.
    if (TokensToPush.size() > 0) {
      for (int i = TokensToPush.size() - 1; i >= 0; i--) {
        this->PP.EnterAnnotationToken(
            SourceRange(Range.getBegin(), Range.getBegin()),
            TokensToPush[i].Kind, TokensToPush[i].Data);
      }
    }
  }
}

// @unreal: END