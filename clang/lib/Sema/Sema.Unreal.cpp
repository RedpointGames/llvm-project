#include "UsedDeclVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDiagnostic.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclFriend.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/PrettyDeclStackTrace.h"
#include "clang/AST/StmtCXX.h"
#include "clang/Basic/DarwinSDKInfo.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/PartialDiagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/Stack.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/HeaderSearch.h"
#include "clang/Lex/HeaderSearchOptions.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Sema/CXXFieldCollector.h"
#include "clang/Sema/DelayedDiagnostic.h"
#include "clang/Sema/EnterExpressionEvaluationContext.h"
#include "clang/Sema/ExternalSemaSource.h"
#include "clang/Sema/Initialization.h"
#include "clang/Sema/MultiplexExternalSemaSource.h"
#include "clang/Sema/ObjCMethodList.h"
#include "clang/Sema/RISCVIntrinsicManager.h"
#include "clang/Sema/Scope.h"
#include "clang/Sema/ScopeInfo.h"
#include "clang/Sema/SemaConsumer.h"
#include "clang/Sema/SemaInternal.h"
#include "clang/Sema/TemplateDeduction.h"
#include "clang/Sema/TemplateInstCallback.h"
#include "clang/Sema/TypoCorrection.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/TimeProfiler.h"
#include <optional>

using namespace clang;
using namespace sema;

void Sema::ActOnUnrealData(SourceLocation TokenLoc, tok::TokenKind Kind,
                           const UnrealSpecifier &UnrealData) {
  if (Kind == tok::TokenKind::annot_unreal_uinterface &&
      UnrealStack.size() == 1 &&
      UnrealStack[0].Kind == tok::TokenKind::annot_unreal_uclass) {
    // This is an expected scenario because the UINTERFACE macro maps
    // to 'UCLASS()' during actual compilation.
    UnrealStack.clear();
  }
  if (UnrealStack.size() != 0 &&
      (Kind == tok::TokenKind::annot_unreal_uclass ||
       Kind == tok::TokenKind::annot_unreal_ufunction ||
       Kind == tok::TokenKind::annot_unreal_ustruct ||
       Kind == tok::TokenKind::annot_unreal_uinterface ||
       Kind == tok::TokenKind::annot_unreal_uproperty)) {
    Diag(TokenLoc, diag::warn_unreal_data_discarded_on_new_specifier);
    for (const auto &Entry : UnrealStack) {
      Diag(Entry.Loc, diag::note_unreal_data_previous_location);
    }
    UnrealStack.clear();
  }
  if (UnrealStack.size() == 0 &&
      (Kind == tok::TokenKind::annot_unreal_specifier ||
       Kind == tok::TokenKind::annot_unreal_metadata_specifier)) {
    assert(false && "Pushing specifier or metadata onto Unreal Stack, but no"
                    "macro was pushed first!");
  }
  UnrealStack.push_back(UnrealSpecifierSema(Kind, UnrealData, TokenLoc));
  assert((UnrealStack.size() < 1000) &&
         "Unreal stack not being consumed by type declaration.");
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wswitch-enum"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4062)
#endif
void Sema::AddUnrealSpecifiersForDecl(Decl *D) {
  if (NamedDecl *ND = dyn_cast<NamedDecl>(D)) {
    while (this->UnrealStack.size() > 0) {
      const auto &Current = this->UnrealStack[0];
      switch (Current.Kind) {
      case tok::annot_unreal_exported: {
        ND->UnrealExported = true;
        break;
      }
      case tok::annot_unreal_uproperty: {
        if (FieldDecl *FD = dyn_cast<FieldDecl>(ND)) {
          ND->UnrealType = UnrealType::UT_UProperty;
        }
        break;
      }
      case tok::annot_unreal_ufunction: {
        if (CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(ND)) {
          ND->UnrealType = UnrealType::UT_UFunction;
        }
        break;
      }
      case tok::annot_unreal_uclass: {
        if (RecordDecl *RD = dyn_cast<RecordDecl>(ND)) {
          ND->UnrealType = UnrealType::UT_UClass;
        }
        break;
      }
      case tok::annot_unreal_uinterface: {
        if (RecordDecl *RD = dyn_cast<RecordDecl>(ND)) {
          ND->UnrealType = UnrealType::UT_UInterface;
        }
        break;
      }
      case tok::annot_unreal_ustruct: {
        if (RecordDecl *RD = dyn_cast<RecordDecl>(ND)) {
          ND->UnrealType = UnrealType::UT_UStruct;
        }
        break;
      }
      case tok::annot_unreal_specifier: {
        if (ND->UnrealType != UnrealType::UT_None) {
          ND->UnrealSpecifiers.push_back(Current.SpecData);
        }
        break;
      }
      case tok::annot_unreal_metadata_specifier: {
        if (ND->UnrealType != UnrealType::UT_None) {
          ND->UnrealMetadata.push_back(Current.SpecData);
        }
        break;
      }
      }
      this->UnrealStack.erase(this->UnrealStack.begin());
    }
  }
}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif

void Sema::ProcessUnrealInterfaceMappings(TagDecl* New) {
  if (CXXRecordDecl *CRD = dyn_cast<CXXRecordDecl>(New)) {
    std::string InterfaceName = New->getName().str();
    if (New->UnrealType == UnrealType::UT_UInterface) {
      if (InterfaceName.size() > 0 && InterfaceName[0] == 'U') {
        InterfaceName[0] = 'I';
        this->ExpectedIInterfaceToUInterfaceAttachments.insert(
            std::pair<std::string, CXXRecordDecl *>(InterfaceName, CRD));
      }
    } else if (New->UnrealType == UnrealType::UT_None &&
               this->ExpectedIInterfaceToUInterfaceAttachments.find(
                   InterfaceName) !=
                   this->ExpectedIInterfaceToUInterfaceAttachments.end()) {
      CXXRecordDecl *UInterfaceDecl =
          this->ExpectedIInterfaceToUInterfaceAttachments[InterfaceName];
      UInterfaceDecl->IInterfaceAttachment = CRD;
      CRD->UInterfaceAttachment = UInterfaceDecl;
      CRD->UnrealType = UnrealType::UT_IInterface;
      this->ExpectedIInterfaceToUInterfaceAttachments.erase(InterfaceName);
    }
  }
}