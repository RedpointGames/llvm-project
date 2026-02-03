/// Matches template arguments within a pack template argument; the inner
/// matcher is compared against each argument of the parameter pack.
///
/// Given
/// \code
///   template<typename T, typename... Params> class A {};
///   A<int, double> a;
///   A<double, int> b;
/// \endcode
///
/// \endcode
/// classTemplateSpecializationDecl(hasAnyTemplateArgument(
///     refersToPack(refersToType(asString("double")))))
///   matches the specialization \c A<int, double>
///   but does not match the specialization \c A<double, int>
AST_MATCHER_P(TemplateArgument, refersToPack,
              internal::Matcher<TemplateArgument>, InnerMatcher) {
  if (Node.getKind() == TemplateArgument::Pack) {
    for (const TemplateArgument &Arg : Node.pack_elements()) {
      BoundNodesTreeBuilder Result(*Builder);
      if (InnerMatcher.matches(Arg, Finder, &Result)) {
        *Builder = std::move(Result);
        return true;
      }
    }
  }
  return false;
}

/// Matches AST nodes that have no child AST nodes that match the
/// provided matcher.
///
/// Usable as: Any Matcher
extern const internal::ArgumentAdaptingMatcherFunc<internal::ForNoneMatcher>
    forNone;

/// Matches AST nodes that have no descendant AST nodes that match the
/// provided matcher.
///
/// Usable as: Any Matcher
extern const internal::ArgumentAdaptingMatcherFunc<
    internal::ForNoDescendantMatcher>
    forNoDescendant;

/// Matches if the matched type is a Plain Old Data (POD) type.
///
/// Given
/// \code
///   class Y
///   {
///   public:
///       int a;
///       std::string b;
///   };
/// \endcode
/// fieldDecl(hasType(qualType(isPODType())))
///   matches Y::a
AST_MATCHER(QualType, isPODType) {
  return Node.isPODType(Finder->getASTContext());
}

/// Matches \c Decls that could have a __dllimport or __dllexport attribute, but
/// don't.
AST_POLYMORPHIC_MATCHER(isMissingDllImportOrExport,
                        AST_POLYMORPHIC_SUPPORTED_TYPES(CXXRecordDecl,
                                                        FunctionDecl,
                                                        VarDecl)) {
  bool PermittedToExport = false;
  if (const CXXRecordDecl *CXXD = dyn_cast<CXXRecordDecl>(&Node)) {
    if (isa<ClassTemplateDecl>(CXXD->getParent()) ||
        isa<ClassTemplateSpecializationDecl>(CXXD->getParent()) ||
        isa<ClassTemplateSpecializationDecl>(CXXD)) {
      // This type declaration is part of a template, and therefore can not be
      // exported.
      return false;
    }
    if (const VarDecl *CXXDVD =
            dyn_cast_or_null<VarDecl>(CXXD->getNextDeclInContext())) {
      if (CXXDVD != nullptr &&
          CXXDVD->getType()->getAsCXXRecordDecl() == CXXD) {
        if (CXXDVD->hasAttr<DLLImportAttr>() ||
            CXXDVD->hasAttr<DLLExportAttr>()) {
          // This type declaration is immediately followed by a variable that
          // uses it, and that variable is exported. This usually means an
          // export of the kind '__declspec(dllexport) class {} A;' where the
          // CXXRecordDecl isn't exported, but 'A' is.
          return false;
        }
      }
    }
    PermittedToExport = CXXD->hasDefinition() &&
                        CXXD->getDefinition() == CXXD && !CXXD->isLambda() &&
                        CXXD->getDescribedClassTemplate() == nullptr &&
                        (isa<TranslationUnitDecl>(CXXD->getDeclContext()) ||
                         isa<NamespaceDecl>(CXXD->getDeclContext()));
  } else if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(&Node)) {
    PermittedToExport = FD->getStorageClass() != SC_Static &&
                        !FD->isInlineSpecified() && !FD->isConstexpr() &&
                        FD->isGlobal();
  } else if (const VarDecl *VD = dyn_cast<VarDecl>(&Node)) {
    PermittedToExport =
        VD->hasGlobalStorage() && VD->getStorageClass() != SC_Static;
  }
  if (const Decl *D = dyn_cast<Decl>(&Node)) {
    bool HasImportOrExportAttr =
        D->hasAttr<DLLImportAttr>() || D->hasAttr<DLLExportAttr>();
    return PermittedToExport && !HasImportOrExportAttr;
  } else {
    return false;
  }
}

/// Matches elaborated `TypeLoc`s that have redundant namespace components.
///
/// Given
/// \code
///   namespace A::B {
///     class D {};
///   }
///
///   namespace A::C {
///     void E() {
///       A::B::D d;
///     }
///   };
/// \endcode
/// elaboratedTypeLoc(hasRedundantNamespacing());
///   matches the `TypeLoc` of the variable declaration of `d`.
AST_MATCHER(ElaboratedTypeLoc, hasRedundantNamespacing) {
  // Check to see if this type is qualified with a namespace.
  auto *NNS = Node.getQualifierLoc().getNestedNameSpecifier();
  if (NNS == nullptr || !NNS->getAsNamespace()) {
    return false;
  }

  // Find the first ancestor node that has a decl context.
  BoundNodesTreeBuilder LocalBuilder;
  if (!Finder->matchesAncestorOf(
          Node, decl(hasDeclContext(anything())).bind("nearest_context"),
          &LocalBuilder, ASTMatchFinder::AncestorMatchMode::AMM_All)) {
    return false;
  }
  class NearestCollectionVisitor : public BoundNodesTreeBuilder::Visitor {
  public:
    const NamespaceDecl *ReceivedND;
    NearestCollectionVisitor() : ReceivedND(nullptr){};
    virtual ~NearestCollectionVisitor() override = default;
    virtual void visitMatch(const BoundNodes &BoundNodesView) override {
      if (this->ReceivedND == nullptr) {
        if (const Decl *FD =
                BoundNodesView.getNodeAs<Decl>("nearest_context")) {
          const DeclContext *DC = FD->getDeclContext();
          if (DC != nullptr) {
            this->ReceivedND =
                cast<NamespaceDecl>(DC->getEnclosingNamespaceContext());
          }
        }
      }
    }
  };
  NearestCollectionVisitor Visitor;
  LocalBuilder.visitMatches(&Visitor);
  if (Visitor.ReceivedND == nullptr) {
    return false;
  }

  // Record all of the identifiers and the namespace decls that make
  // up the hierarchy of our namespace decl context. We use this to detect
  // when a type specification might be deeply specifying to avoid
  // ambiguity issues.
  llvm::DenseMap<llvm::StringRef, llvm::SmallDenseSet<const NamespaceDecl *, 4>>
      NamespacesInContextHierarchy;
  {
    const NamespaceDecl *NS = Visitor.ReceivedND;
    while (NS != nullptr) {
      if (auto *II = NS->getIdentifier()) {
        NamespacesInContextHierarchy[II->getName()].insert(NS);
      }
      auto *NSP = NS->getParent();
      while (NSP != nullptr && !isa<NamespaceDecl>(NSP)) {
        NSP = NSP->getParent();
      }
      if (NSP) {
        NS = cast<NamespaceDecl>(NSP);
      } else {
        break;
      }
    }
  }

  // Start at first leaf of NNS, and go upward to see whether any
  // namespace elements of the NNS enclose the nearest declaration
  // context.
  {
    auto *Current = NNS;
    bool Disambiguating = false;
    while (Current != nullptr &&
           Current->getKind() == NestedNameSpecifier::Namespace) {
      if (auto *NS = Current->getAsNamespace()) {
        if (auto *II = NS->getIdentifier()) {
          if (NamespacesInContextHierarchy[II->getName()].size() > 0) {
            // The current namespace component in our type specifier matches
            // the name in our hierarchy.
            if (!NamespacesInContextHierarchy[II->getName()].contains(NS)) {
              // The name in our type specifier points to a different namespace
              // than the one in our hierarchy, so the parent of this specifier
              // will be disambiguating.
              Disambiguating = true;
            }
          }
        }

        if (NS->Encloses(Visitor.ReceivedND) &&
            !NS->Equals(Visitor.ReceivedND)) {
          if (Disambiguating) {
            // We need to disambiguate, so allow one entry in the type specifier
            // to be "redundant" (really it's just re-anchoring the specifiers
            // that come after it though).
            Disambiguating = false;
          } else {
            // Redundant! A namespace this specifier mentions already encloses
            // the declaration context that this specifier is being used in.
            return true;
          }
        }
      }
      Current = Current->getPrefix();
    }
  }
  return false;
}