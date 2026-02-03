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