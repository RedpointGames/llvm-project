/// Matches nodes of type T that have no child nodes of type ChildT for
/// which a specified child matcher matches. ChildT must be an AST base
/// type.
/// ForNoneMatcher will only match if none of the child nodes match
/// the inner matcher.
template <typename T, typename ChildT>
class ForNoneMatcher : public MatcherInterface<T> {
  static_assert(IsBaseType<ChildT>::value,
                "for none only accepts base type matcher");

  DynTypedMatcher InnerMatcher;

public:
  explicit ForNoneMatcher(const Matcher<ChildT> &InnerMatcher)
      : InnerMatcher(InnerMatcher) {}

  bool matches(const T &Node, ASTMatchFinder *Finder,
               BoundNodesTreeBuilder *Builder) const override {
    BoundNodesTreeBuilder MatchingBuilder(*Builder);
    bool AnyMatched = Finder->matchesChildOf(
        Node, this->InnerMatcher, &MatchingBuilder, ASTMatchFinder::BK_All);
    if (!AnyMatched) {
      // We didn't iterate over any nodes that matched, so
      // Builder would be empty. This is a success case.
      return true;
    }
    // Otherwise remove from Builder any entries that we
    // also have in MatchingBuilder because we want to leave
    // only the remaining entries.
    return Builder->removeBindings(
        [&MatchingBuilder](const internal::BoundNodesMap &Nodes) {
          return MatchingBuilder.contains(Nodes);
        });
  }
};

/// Matches nodes of type T that have no descendant node of
/// type DescendantT for which the given inner matcher matches.
///
/// DescendantT must be an AST base type.
/// ForNoDescendantMatcher only matches if none of the descendant nodes
/// match.
template <typename T, typename DescendantT>
class ForNoDescendantMatcher : public MatcherInterface<T> {
  static_assert(IsBaseType<DescendantT>::value,
                "for no descendant only accepts base type matcher");

  DynTypedMatcher DescendantMatcher;

public:
  explicit ForNoDescendantMatcher(const Matcher<DescendantT> &DescendantMatcher)
      : DescendantMatcher(DescendantMatcher) {}

  bool matches(const T &Node, ASTMatchFinder *Finder,
               BoundNodesTreeBuilder *Builder) const override {
    BoundNodesTreeBuilder MatchingBuilder(*Builder);
    bool AnyMatched = 
        Finder->matchesDescendantOf(Node, this->DescendantMatcher,
                                    &MatchingBuilder, ASTMatchFinder::BK_All);
    if (!AnyMatched) {
      // We didn't iterate over any nodes that matched, so
      // Builder would be empty. This is a success case.
      return true;
    }
    // Otherwise remove from Builder any entries that we
    // also have in MatchingBuilder because we want to leave
    // only the remaining entries.
    return Builder->removeBindings(
        [&MatchingBuilder](const internal::BoundNodesMap &Nodes) {
          return MatchingBuilder.contains(Nodes);
        });
  }
};