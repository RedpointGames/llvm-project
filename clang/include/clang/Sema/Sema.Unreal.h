// Unreal stacks.
struct UnrealSpecifierSema {
  tok::TokenKind Kind;
  clang::UnrealSpecifier SpecData;
  clang::SourceLocation Loc;
  UnrealSpecifierSema(tok::TokenKind InKind,
                      const clang::UnrealSpecifier &InSpecData,
                      const clang::SourceLocation &InLoc)
      : Kind(InKind), SpecData(InSpecData), Loc(InLoc){};
};
std::vector<UnrealSpecifierSema> UnrealStack;
std::map<std::string, CXXRecordDecl *>
    ExpectedIInterfaceToUInterfaceAttachments;

void ActOnUnrealData(SourceLocation TokenLoc, tok::TokenKind Kind,
                      const UnrealSpecifier &UnrealData);

/// Called to add specifiers from the Unreal stack.
void AddUnrealSpecifiersForDecl(Decl *RD);

void ProcessUnrealInterfaceMappings(TagDecl* New);