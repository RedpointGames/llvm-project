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