#include "ClangRulesets.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/DeclBase.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/Dynamic/Parser.h"
#include "clang/Basic/DiagnosticSema.h"
#include "clang/Basic/SourceMgrAdapter.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Sema/Lookup.h"
#include "llvm/Support/Mutex.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#if defined(_WIN32)
#include "llvm/Support/Windows/WindowsSupport.h"
#endif

using namespace clang;

#define RULESET_ENABLE_TIMING 0
#define RULESET_ENABLE_TIMING_ALWAYS 0
#define RULESET_ENABLE_TRACING_CORE 0
#define RULESET_ENABLE_TRACING_CONFIG 0
#define RULESET_ENABLE_TRACING_CONTEXT 0
#define RULESET_ENABLE_TRACING_MATCHER 0
#define RULESET_ENABLE_TRACING_RULESET 0
#define RULESET_ENABLE_TRACING_IWYU 0
#define RULESET_ENABLE_TRACING_IWYU_DECL 0
#define RULESET_ENABLE_TRACING_IWYU_PREPROCESSOR 0
#define RULESET_SKIP_ALL_ANALYSIS 0

#if RULESET_ENABLE_TRACING_CORE
#define RULESET_TRACE_CORE(x) llvm::errs() << "Core: " << x;
#else
#define RULESET_TRACE_CORE(x)
#endif
#if RULESET_ENABLE_TRACING_CONFIG
#define RULESET_TRACE_CONFIG(x) llvm::errs() << "Config: " << x;
#define RULESET_TRACE_CONFIG_NO_PREFIX(x) llvm::errs() << x;
#else
#define RULESET_TRACE_CONFIG(x)
#define RULESET_TRACE_CONFIG_NO_PREFIX(x)
#endif
#if RULESET_ENABLE_TRACING_CONTEXT
#define RULESET_TRACE_CONTEXT(x) llvm::errs() << "Context: " << x;
#else
#define RULESET_TRACE_CONTEXT(x)
#endif
#if RULESET_ENABLE_TRACING_MATCHER
#define RULESET_TRACE_MATCHER(x) llvm::errs() << "Matcher: " << x;
#else
#define RULESET_TRACE_MATCHER(x)
#endif
#if RULESET_ENABLE_TRACING_RULESET
#define RULESET_TRACE_RULESET(x) llvm::errs() << "Ruleset: " << x;
#define RULESET_TRACE_RULESET_MUTEX(m, x)                                      \
  {                                                                            \
    m.lock();                                                                  \
    llvm::errs() << "Ruleset:" << x;                                           \
    m.unlock();                                                                \
  }
#define RULESET_TRACE_RULESET_MUTEX_WITH_DECL_DUMP(m, d, x)                    \
  {                                                                            \
    m.lock();                                                                  \
    llvm::errs() << "Ruleset:" << x;                                           \
    d->dump();                                                                 \
    m.unlock();                                                                \
  }
#else
#define RULESET_TRACE_RULESET(x)
#define RULESET_TRACE_RULESET_MUTEX(m, x)
#define RULESET_TRACE_RULESET_MUTEX_WITH_DECL_DUMP(m, d, x)
#endif
#if RULESET_ENABLE_TRACING_IWYU
#define RULESET_TRACE_IWYU(x) llvm::errs() << "IWYU: " << x;
#define RULESET_TRACE_IWYU_MUTEX(m, x)                                         \
  {                                                                            \
    m.lock();                                                                  \
    llvm::errs() << x;                                                         \
    m.unlock();                                                                \
  }
#else
#define RULESET_TRACE_IWYU(x)
#define RULESET_TRACE_IWYU_MUTEX(m, x)
#endif
#if RULESET_ENABLE_TRACING_IWYU_DECL
#define RULESET_TRACE_IWYU_DECL_MUTEX_WITH_DECL_DUMP(m, d, x)                  \
  {                                                                            \
    m.lock();                                                                  \
    llvm::errs() << "IWYU C++ decl:" << x;                                     \
    d->dump();                                                                 \
    m.unlock();                                                                \
  }
#else
#define RULESET_TRACE_IWYU_DECL_MUTEX_WITH_DECL_DUMP(m, d, x)
#endif
#if RULESET_ENABLE_TRACING_IWYU_PREPROCESSOR
#define RULESET_TRACE_IWYU_PREPROCESSOR(x)                                     \
  llvm::errs() << "IWYU preprocessor: " << x;
#else
#define RULESET_TRACE_IWYU_PREPROCESSOR(x)
#endif

#if RULESET_ENABLE_TIMING
#if RULESET_ENABLE_TIMING_ALWAYS
#define RULESET_TIME_REGION_ANALYSIS(CI, Name, Timing)                         \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      nullptr, (Timing) == nullptr                                             \
                   ? nullptr                                                   \
                   : ((Timing)->RulesetAnalysisOtherTimer.get()))
#define RULESET_TIME_REGION_BEFORE_ANALYSIS(CI, Name, Timing, Timer)           \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      nullptr, (Timing) == nullptr ? nullptr : ((Timing)->Timer.get()))
#define RULESET_TIME_REGION_DURING_ANALYSIS(CI, Name, Timing, Timer)           \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      (Timing) == nullptr ? nullptr                                            \
                          : ((Timing)->RulesetAnalysisOtherTimer.get()),       \
      (Timing) == nullptr ? nullptr : ((Timing)->Timer.get()))
#define RULESET_TIME_REGION_DURING_ANALYSIS_NESTED(CI, Name, Timing,           \
                                                   CurrentTimer, DesiredTimer) \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      (Timing) == nullptr ? nullptr : ((Timing)->CurrentTimer.get()),          \
      (Timing) == nullptr ? nullptr : ((Timing)->DesiredTimer.get()))
#else
#define RULESET_TIME_REGION_ANALYSIS(CI, Name, Timing)                         \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      nullptr, (!(CI).hasFrontendTimer())                                      \
                   ? nullptr                                                   \
                   : ((Timing) == nullptr                                      \
                          ? nullptr                                            \
                          : ((Timing)->RulesetAnalysisOtherTimer.get())))
#define RULESET_TIME_REGION_BEFORE_ANALYSIS(CI, Name, Timing, Timer)           \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      nullptr,                                                                 \
      (!(CI).hasFrontendTimer())                                               \
          ? nullptr                                                            \
          : ((Timing) == nullptr ? nullptr : ((Timing)->Timer.get())))
#define RULESET_TIME_REGION_DURING_ANALYSIS(CI, Name, Timing, Timer)           \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      (!(CI).hasFrontendTimer())                                               \
          ? nullptr                                                            \
          : ((Timing) == nullptr                                               \
                 ? nullptr                                                     \
                 : ((Timing)->RulesetAnalysisOtherTimer.get())),               \
      (!(CI).hasFrontendTimer())                                               \
          ? nullptr                                                            \
          : ((Timing) == nullptr ? nullptr : ((Timing)->Timer.get())))
#define RULESET_TIME_REGION_DURING_ANALYSIS_NESTED(CI, Name, Timing,           \
                                                   CurrentTimer, DesiredTimer) \
  clang::rulesets::RulesetTimeRegion Name(                                     \
      (!(CI).hasFrontendTimer())                                               \
          ? nullptr                                                            \
          : ((Timing) == nullptr ? nullptr : ((Timing)->CurrentTimer.get())),  \
      (!(CI).hasFrontendTimer())                                               \
          ? nullptr                                                            \
          : ((Timing) == nullptr ? nullptr : ((Timing)->DesiredTimer.get())))
#endif
#else
#define RULESET_TIME_REGION_ANALYSIS(CI, Name, Timing)
#define RULESET_TIME_REGION_BEFORE_ANALYSIS(CI, Name, Timing, Timer)
#define RULESET_TIME_REGION_DURING_ANALYSIS(CI, Name, Timing, Timer)
#define RULESET_TIME_REGION_DURING_ANALYSIS_NESTED(CI, Name, Timing,           \
                                                   CurrentTimer, DesiredTimer)
#endif

namespace clang::rulesets {

class RulesetTimeRegion : public llvm::TimeRegion {
private:
  llvm::Timer *SuspendedTimer;

public:
  explicit RulesetTimeRegion(llvm::Timer *SuspendingTimer,
                             llvm::Timer *ActiveTimer)
      : llvm::TimeRegion(ActiveTimer), SuspendedTimer(SuspendingTimer) {
    if (SuspendingTimer)
      SuspendingTimer->stopTimer();
  }
  ~RulesetTimeRegion() {
    if (SuspendedTimer)
      SuspendedTimer->startTimer();
  }
};

} // namespace clang::rulesets

namespace clang::rulesets::config {

/// The severity level that diagnostics should emit at for a particular Clang
/// rule or ruleset.
enum ClangRulesSeverity : int8_t {
  /// The severity level is not set, which indicates a default of 'Warning' in
  /// configuration files.
  CRS_NotSet,
  /// This rule is silenced and will not be evaluated. You can use this to
  /// silence rules in a more
  /// deeply nested .clang-rules file where that rule was activated by a
  /// .clang-rules file higher
  /// in the filesystem hierarchy.
  CRS_Silence,
  /// Diagnostics will be emitted at the 'remark' level.
  CRS_Info,
  /// Diagnostics will be emitted at the 'warning' level.
  CRS_Warning,
  /// Diagnostics will be emitted at the 'error' level.
  CRS_Error,
};

/// Determines whether IWYU analysis should be enabled for files in this folder.
enum ClangRulesIWYUAnalysis : int8_t {
  /// IWYU analysis is not turned on or off, and the setting will be inherited
  /// from the parent folder.
  CRIA_NotSet,
  /// IWYU analysis is turned off.
  CRIA_Off,
  /// IWYU analysis is turned on.
  CRIA_On,
};

/// Determines whether the Clang AST matcher operates in "AsIs" or
/// "IgnoreUnlessSpelledInSource" traversal mode.
enum ClangRulesTraversalMode : int8_t {
  /// Traverse AST nodes even if they don't exist in source code.
  CRTM_AsIs,
  /// Only traverse into AST nodes that are explicitly present in the source
  /// code.
  CRTM_IgnoreUnlessSpelledInSource,
};

/// Defines a static analysis rule to run during compilation.
struct ClangRulesRule {
  /// The unique name of the rule sans namespace. You can reference rules in
  /// rulesets by this name when in the same namespace, or by `namespace/name`
  /// from rulesets in other namespaces.
  std::string Name;
  /// The Clang AST matcher to evaluate against top-level declarations in the
  /// AST.
  std::string Matcher;
  /// Specifies the traversal mode for the AST matcher.
  ClangRulesTraversalMode TraversalMode;
  /// The compiler diagnostic message to emit at the callsite when this static
  /// analysis rule matches.
  std::string ErrorMessage;
  /// The name of the bound node in the matcher which indicates the location to
  /// emit the compiler diagnostic at.
  std::string Callsite;
  /// Additional hint diagnostics to emit when this static analysis rule
  /// matches. The key is the name of the bound node in the matcher and the
  /// value is the diagnostic message to emit (at 'note' severity).
  std::map<std::string, std::string> Hints;
  /// The runtime matcher value after the matcher expression has been parsed and
  /// loaded by Clang.
  std::optional<clang::ast_matchers::internal::DynTypedMatcher> MatcherParsed;
  /// If true, this rule only applies when the compilation triple targets
  /// Windows. This can be used for rules which match on Windows-specific AST
  /// nodes (such as '__declspec(dllexport)').
  bool WindowsOnly;
  /// If true, the AST of bound nodes in the AST matcher expression will be
  /// dumped to the compiler console output when this rule matches. This can be
  /// used to create and diagnose matcher expressions.
  bool Debug;
};

/// A mapping from a ruleset to the previously defined rule and severity to
/// raise it at. Rule entries in rulesets can be declared matching this
/// structure, or they can declared as a string which will be implicitly mapped
/// to the 'Name' field, with 'Severity' set to 'NotSet' (which means it will
/// inherit from the ruleset's default severity).
struct ClangRulesRulesetRule {
  /// Either 'name' for rules defined in the same namespace, or 'namespace/name'
  /// for rules defined in other namespaces.
  std::string Name;
  /// The severity to emit the rule at when it matches.
  ClangRulesSeverity Severity;
};

/// A mapping from a ruleset to another previously defined ruleset. Ruleset
/// entries in rulesets can be declared matching this structure, or they can
/// declared as a string which will be implicitly mapped to the 'Name' field,.
struct ClangRulesRulesetRuleset {
  /// Either 'name' for rulesets defined in the same namespace, or
  /// 'namespace/name' for rulesets defined in other namespaces.
  std::string Name;
};

/// Defines a static analysis ruleset to apply to this directory and
/// subdirectories, with a set of rules to enable and/or set the severity of.
struct ClangRulesRuleset {
  /// The unique name of the ruleset sans namespace. You can reference rulesets
  /// in other rulesets by this name when in the same namespace, or by
  /// `namespace/name` from rulesets in other namespaces.
  std::string Name;
  /// The default severity for rule diagnostics to emit at for rules included by
  /// this ruleset. This is the severity used when an entry in the 'Rules' array
  /// does not have a specific severity.
  ClangRulesSeverity Severity;
  /// The rules to enable or update the severity of when this ruleset is active.
  std::vector<ClangRulesRulesetRule> Rules;
  /// The rulesets to include as part of this ruleset when this ruleset is
  /// active.
  std::vector<ClangRulesRulesetRuleset> Rulesets;
  /// By default, rulesets in a .clang-rules file are both defined and made
  /// active for the directory and subdirectories it's declared in. If you set
  /// 'DefineOnly: true' for a ruleset, then the ruleset is defined and
  /// available to use in .clang-rules files more deeply nested in the
  /// hierarchy, but won't be activated for the directory it's defined in. This
  /// allows you to declare a ruleset and use it in more deeply nested rulesets.
  bool DefineOnly;
};

/// Maps to a configuration provided by a .clang-rules file.
struct ClangRules {
  /// The namespace of rules and rulesets defined in this configuration
  /// document.
  std::string Namespace;
  /// The list of rules that are defined in this document. Rules do not apply
  /// unless they're enabled by a ruleset.
  std::vector<ClangRulesRule> Rules;
  /// The list of rulesets that are defined in this document.
  std::vector<ClangRulesRuleset> Rulesets;
  /// Whether or not IWYU analysis should run and diagnostics emitted.
  ClangRulesIWYUAnalysis IWYUAnalysis;
};

} // namespace clang::rulesets::config

LLVM_YAML_IS_STRING_MAP(std::string);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRulesetRule);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRulesetRuleset);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRule);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRuleset);
LLVM_YAML_IS_DOCUMENT_LIST_VECTOR(clang::rulesets::config::ClangRules);

namespace llvm::yaml {

template <>
struct ScalarEnumerationTraits<clang::rulesets::config::ClangRulesSeverity> {
  static void enumeration(IO &IO,
                          clang::rulesets::config::ClangRulesSeverity &Value) {
    IO.enumCase(Value, "NotSet",
                clang::rulesets::config::ClangRulesSeverity::CRS_NotSet);
    IO.enumCase(Value, "Silence",
                clang::rulesets::config::ClangRulesSeverity::CRS_Silence);
    IO.enumCase(Value, "Info",
                clang::rulesets::config::ClangRulesSeverity::CRS_Info);
    IO.enumCase(Value, "Warning",
                clang::rulesets::config::ClangRulesSeverity::CRS_Warning);
    IO.enumCase(Value, "Error",
                clang::rulesets::config::ClangRulesSeverity::CRS_Error);
  }
};

template <>
struct ScalarTraits<clang::rulesets::config::ClangRulesIWYUAnalysis> {
  static void output(const clang::rulesets::config::ClangRulesIWYUAnalysis &Val,
                     void *, raw_ostream &Out) {
    switch (Val) {
    case clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_On:
      Out << "On";
      break;
    case clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_Off:
      Out << "Off";
      break;
    default:
      Out << "NotSet";
      break;
    }
  }
  static StringRef input(StringRef Scalar, void *,
                         clang::rulesets::config::ClangRulesIWYUAnalysis &Val) {
    if (Scalar == "NotSet") {
      Val = clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_NotSet;
    } else if (std::optional<bool> Parsed = parseBool(Scalar)) {
      Val = (*Parsed)
                ? clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_On
                : clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_Off;
    } else {
      Val = clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_NotSet;
    }
    return StringRef();
  }
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template <>
struct ScalarEnumerationTraits<
    clang::rulesets::config::ClangRulesTraversalMode> {
  static void
  enumeration(IO &IO, clang::rulesets::config::ClangRulesTraversalMode &Value) {
    IO.enumCase(Value, "AsIs",
                clang::rulesets::config::ClangRulesTraversalMode::CRTM_AsIs);
    IO.enumCase(Value, "IgnoreUnlessSpelledInSource",
                clang::rulesets::config::ClangRulesTraversalMode::
                    CRTM_IgnoreUnlessSpelledInSource);
  }
};

template <> struct MappingTraits<clang::rulesets::config::ClangRulesRule> {
  static void mapping(IO &IO, clang::rulesets::config::ClangRulesRule &Rule) {
    IO.mapRequired("Name", Rule.Name);
    IO.mapRequired("Matcher", Rule.Matcher);
    IO.mapOptional("TraversalMode", Rule.TraversalMode,
                   clang::rulesets::config::ClangRulesTraversalMode::CRTM_AsIs);
    IO.mapRequired("ErrorMessage", Rule.ErrorMessage);
    IO.mapRequired("Callsite", Rule.Callsite);
    IO.mapOptional("Hints", Rule.Hints);
    IO.mapOptional("WindowsOnly", Rule.WindowsOnly, false);
    IO.mapOptional("Debug", Rule.Debug, false);
  }
};

template <>
struct MappingTraits<clang::rulesets::config::ClangRulesRulesetRule> {
  static void mapping(IO &IO,
                      clang::rulesets::config::ClangRulesRulesetRule &Rule) {
    if (IO.getNodeKind() == NodeKind::Scalar) {
      // Allow rules for rulesets to be encoded as plain strings.
      llvm::StringRef RuleName = Rule.Name;
      IO.scalarString(RuleName, QuotingType::Double);
      Rule.Name = RuleName;
      Rule.Severity = clang::rulesets::config::ClangRulesSeverity::CRS_NotSet;
    } else {
      // Allow rules for rulesets to specify name and severity.
      IO.mapRequired("Name", Rule.Name);
      IO.mapOptional("Severity", Rule.Severity,
                     clang::rulesets::config::ClangRulesSeverity::CRS_NotSet);
    }
  }
};

template <>
struct MappingTraits<clang::rulesets::config::ClangRulesRulesetRuleset> {
  static void
  mapping(IO &IO, clang::rulesets::config::ClangRulesRulesetRuleset &Ruleset) {
    if (IO.getNodeKind() == NodeKind::Scalar) {
      // Allow rulesets for rulesets to be encoded as plain strings.
      llvm::StringRef RuleName = Ruleset.Name;
      IO.scalarString(RuleName, QuotingType::Double);
      Ruleset.Name = RuleName;
    } else {
      // Allow rulessets for rulesets to specify name.
      IO.mapRequired("Name", Ruleset.Name);
    }
  }
};

template <> struct MappingTraits<clang::rulesets::config::ClangRulesRuleset> {
  static void mapping(IO &IO,
                      clang::rulesets::config::ClangRulesRuleset &Ruleset) {
    IO.mapRequired("Name", Ruleset.Name);
    IO.mapOptional("Severity", Ruleset.Severity,
                   clang::rulesets::config::ClangRulesSeverity::CRS_Warning);
    IO.mapOptional("Rules", Ruleset.Rules);
    IO.mapOptional("Rulesets", Ruleset.Rulesets);
    IO.mapOptional("DefineOnly", Ruleset.DefineOnly, false);
  }
};

template <> struct MappingTraits<clang::rulesets::config::ClangRules> {
  static void mapping(IO &IO, clang::rulesets::config::ClangRules &Rules) {
    IO.mapRequired("Namespace", Rules.Namespace);
    IO.mapOptional("Rulesets", Rules.Rulesets);
    IO.mapOptional("Rules", Rules.Rules);
    if (!IO.outputting() ||
        Rules.IWYUAnalysis !=
            clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_NotSet) {
      IO.mapOptional(
          "IWYUAnalysis", Rules.IWYUAnalysis,
          clang::rulesets::config::ClangRulesIWYUAnalysis::CRIA_NotSet);
    }
  }
};

} // namespace llvm::yaml

namespace clang::rulesets {

struct ClangRulesetsEffectiveRule {
  // Pointer to memory inside a loaded config::ClangRules.
  config::ClangRulesRule *Rule;
  config::ClangRulesSeverity Severity;
};

struct ClangRulesetsEffectiveConfig {
  std::map<std::string, ClangRulesetsEffectiveRule> EffectiveRules;
  config::ClangRulesIWYUAnalysis EffectiveIWYUAnalysis; // @note: NotSet is 0.
};

struct ClangRulesetsDirectoryState {
public:
  // If this directory contained a .clang-rules file, this is the on-disk
  // configurations that were loaded (the YAML file may contain multiple
  // configuration documents, so this is a vector).
  std::unique_ptr<std::vector<config::ClangRules>> ActualOnDiskConfigs;
  // The parent directory of this directory, if this directory is not
  // a root.
  OptionalDirectoryEntryRef ParentDirectory;
  // Have we materialised the resolution fields (even if they resolved
  // to no config at all)?
  bool Materialized;
  // The effective rules config that applies to this directory.
  ClangRulesetsEffectiveConfig *EffectiveConfig;
};

class ClangRulesetsTiming {
#if RULESET_ENABLE_TIMING
public:
  std::unique_ptr<llvm::TimerGroup> RulesetTimerGroup;
  std::unique_ptr<llvm::Timer> RulesetLoadClangRulesTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisOtherTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisFileCheckTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisFileChangeTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisMaterializationTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisExecuteTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisScheduleTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisWaitTimer;
  std::unique_ptr<llvm::Timer> RulesetIWYUAnalysisTimer;
  std::unique_ptr<llvm::Timer> RulesetIWYUCppCaptureFileCheckTimer;
  std::unique_ptr<llvm::Timer> RulesetIWYUCppCaptureMaterializationTimer;
  std::unique_ptr<llvm::Timer> RulesetIWYUCppCaptureDependencyInsertTimer;
  std::unique_ptr<llvm::Timer>
      RulesetIWYUPreprocessorCaptureIncludeFileCheckTimer;
  std::unique_ptr<llvm::Timer>
      RulesetIWYUPreprocessorCaptureIncludeMaterializationTimer;
  std::unique_ptr<llvm::Timer>
      RulesetIWYUPreprocessorCaptureIncludeDependencyInsertTimer;
  std::unique_ptr<llvm::Timer>
      RulesetIWYUPreprocessorCaptureMacroFileCheckTimer;
  std::unique_ptr<llvm::Timer>
      RulesetIWYUPreprocessorCaptureMacroMaterializationTimer;
  std::unique_ptr<llvm::Timer>
      RulesetIWYUPreprocessorCaptureMacroDependencyInsertTimer;

  ClangRulesetsTiming()
      : RulesetTimerGroup(std::make_unique<llvm::TimerGroup>(
            "ruleset", "Clang ruleset analysis")),
        RulesetLoadClangRulesTimer(std::make_unique<llvm::Timer>(
            "ruleset-load", "Load .clang-rules files during preprocessor",
            *RulesetTimerGroup)),
        RulesetAnalysisOtherTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-other",
            "Time spent elsewhere in ruleset analysis", *RulesetTimerGroup)),
        RulesetAnalysisFileCheckTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-file-check",
            "Checking whether or not the current file has changed as Decls are "
            "iterated through",
            *RulesetTimerGroup)),
        RulesetAnalysisFileChangeTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-file-change",
            "Calculating what rules should be used when the current file "
            "changes as Decls are iterated through",
            *RulesetTimerGroup)),
        RulesetAnalysisMaterializationTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-materialize",
            "Materialize loaded rules into effective rules during top-level "
            "AST traversal",
            *RulesetTimerGroup)),
        RulesetAnalysisExecuteTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-execute",
            "Time spent running scheduling work on background threads",
            *RulesetTimerGroup)),
        RulesetAnalysisScheduleTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-schedule",
            "Time spent running analysis in foreground thread",
            *RulesetTimerGroup)),
        RulesetAnalysisWaitTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis-wait",
            "Time spent blocked waiting for analysis to complete on background "
            "threads",
            *RulesetTimerGroup)),
        RulesetIWYUAnalysisTimer(std::make_unique<llvm::Timer>(
            "ruleset-iwyu-analysis",
            "Time spent running include-what-you-use analysis",
            *RulesetTimerGroup)),
        RulesetIWYUCppCaptureFileCheckTimer(std::make_unique<llvm::Timer>(
            "ruleset-iwyu-cpp-capture-file",
            "Time spent determining what the current file is for "
            "include-what-you-use C++ AST dependency tracking",
            *RulesetTimerGroup)),
        RulesetIWYUCppCaptureMaterializationTimer(std::make_unique<llvm::Timer>(
            "ruleset-iwyu-cpp-capture-materialize",
            "Materializing loaded rules into effective rules during "
            "include-what-you-use C++ AST dependency tracking",
            *RulesetTimerGroup)),
        RulesetIWYUCppCaptureDependencyInsertTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-cpp-capture-deps",
                "Time spent inserting include-what-you-use dependencies into "
                "the state for C++ AST dependency tracking",
                *RulesetTimerGroup)),
        RulesetIWYUPreprocessorCaptureIncludeFileCheckTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-preprocessor-capture-include-file",
                "Time spent determining what the current file is for "
                "include-what-you-use preprocessor #include pragma tracking",
                *RulesetTimerGroup)),
        RulesetIWYUPreprocessorCaptureIncludeMaterializationTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-preprocessor-capture-include-materialize",
                "Materializing loaded rules into effective rules during "
                "include-what-you-use preprocessor #include pragma tracking",
                *RulesetTimerGroup)),
        RulesetIWYUPreprocessorCaptureIncludeDependencyInsertTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-preprocessor-capture-include-deps",
                "Time spent inserting include-what-you-use dependencies into "
                "the state for preprocessor #include pragma tracking",
                *RulesetTimerGroup)),
        RulesetIWYUPreprocessorCaptureMacroFileCheckTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-preprocessor-capture-macro-file",
                "Time spent determining what the current file is for "
                "include-what-you-use preprocessor macro usage tracking",
                *RulesetTimerGroup)),
        RulesetIWYUPreprocessorCaptureMacroMaterializationTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-preprocessor-capture-macro-materialize",
                "Materializing loaded rules into effective rules during "
                "include-what-you-use preprocessor macro usage tracking",
                *RulesetTimerGroup)),
        RulesetIWYUPreprocessorCaptureMacroDependencyInsertTimer(
            std::make_unique<llvm::Timer>(
                "ruleset-iwyu-preprocessor-capture-macro-deps",
                "Time spent inserting include-what-you-use dependencies into "
                "the state for preprocessor macro usage tracking",
                *RulesetTimerGroup)) {}
#endif
};

clang::DiagnosticIDs::Level
convertDiagnosticLevel(config::ClangRulesSeverity Severity) {
  clang::DiagnosticIDs::Level DiagnosticLevel =
      clang::DiagnosticIDs::Level::Remark;
  switch (Severity) {
  case config::ClangRulesSeverity::CRS_Silence:
  case config::ClangRulesSeverity::CRS_Info:
    DiagnosticLevel = clang::DiagnosticIDs::Level::Remark;
    break;
  case config::ClangRulesSeverity::CRS_Warning:
  case config::ClangRulesSeverity::CRS_NotSet:
    DiagnosticLevel = clang::DiagnosticIDs::Level::Warning;
    break;
  case config::ClangRulesSeverity::CRS_Error:
    DiagnosticLevel = clang::DiagnosticIDs::Level::Error;
    break;
  }
  return DiagnosticLevel;
}

class ClangRulesetsState {
private:
  bool ThreadingEnabled;
  clang::CompilerInstance &CI;
  clang::SourceManager &SrcMgr;

public:
  llvm::DenseMap<DirectoryEntryRef, ClangRulesetsDirectoryState> Dirs;

private:
  std::unique_ptr<ClangRulesetsTiming> Timing;
  std::vector<ClangRulesetsEffectiveConfig *> CreatedEffectiveConfigs;
  llvm::StringMap<config::ClangRulesRule *> RuleByNamespacedName;
  llvm::StringMap<config::ClangRulesRuleset *> RulesetByNamespacedName;
  llvm::DenseMap<FileEntryRef, llvm::DenseSet<FileEntryRef>> IWYUDependencyTree;
  llvm::DenseMap<FileEntryRef, llvm::DenseMap<FileEntryRef, SourceLocation>>
      IWYUIncludeTree;
  clang::FileID LastIWYUFileID;
  clang::OptionalFileEntryRef LastIWYUFileEntry;

public:
  ClangRulesetsState(bool InThreadingEnabled, clang::CompilerInstance &InCI)
      : ThreadingEnabled(InThreadingEnabled), CI(InCI),
        SrcMgr(InCI.getSourceManager()), Dirs(),
        Timing(std::make_unique<ClangRulesetsTiming>()),
        CreatedEffectiveConfigs(), RuleByNamespacedName(),
        RulesetByNamespacedName(), IWYUDependencyTree(), IWYUIncludeTree(),
        LastIWYUFileID(), LastIWYUFileEntry(){};
  ClangRulesetsState(const ClangRulesetsState &) = delete;
  ClangRulesetsState(ClangRulesetsState &&) = delete;
  ~ClangRulesetsState() {
    for (const auto &Config : this->CreatedEffectiveConfigs) {
      delete Config;
    }
  }

  ClangRulesetsTiming *getTiming() { return this->Timing.get(); }

public:
  void iwyuTrackInclusionDirective(SourceLocation IncludingHashLoc,
                                   OptionalFileEntryRef IncludedFile) {
    llvm::DenseMap<DirectoryEntryRef, ClangRulesetsDirectoryState>::iterator
        DirState;
    {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(
          this->CI, Timer, this->Timing,
          RulesetIWYUPreprocessorCaptureIncludeFileCheckTimer);
      if (!IncludedFile || !IncludingHashLoc.isFileID()) {
        return;
      }
      auto IncludingFileID =
          SrcMgr.getFileID(SrcMgr.getFileLoc(IncludingHashLoc));
      if (IncludingFileID != LastIWYUFileID) {
        LastIWYUFileID = IncludingFileID;
        LastIWYUFileEntry = SrcMgr.getFileEntryRefForID(LastIWYUFileID);
      }
      if (!LastIWYUFileEntry) {
        return;
      }
      DirState = this->Dirs.find(LastIWYUFileEntry->getDir());
      if (DirState == this->Dirs.end()) {
        return;
      }
    }
    {
      if (!DirState->second.Materialized) {
        RULESET_TIME_REGION_BEFORE_ANALYSIS(
            this->CI, MaterializationTimer, this->Timing,
            RulesetIWYUPreprocessorCaptureIncludeMaterializationTimer);
        this->materializeDirectoryState(DirState->second, CI.getDiagnostics());
      }

      if (DirState->second.EffectiveConfig == nullptr ||
          DirState->second.EffectiveConfig->EffectiveIWYUAnalysis !=
              config::ClangRulesIWYUAnalysis::CRIA_On) {
        return;
      }
    }
    {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(
          this->CI, Timer, this->Timing,
          RulesetIWYUPreprocessorCaptureIncludeDependencyInsertTimer);
      auto &List = IWYUIncludeTree.getOrInsertDefault(*LastIWYUFileEntry);
      List.try_emplace(*IncludedFile, IncludingHashLoc);
      RULESET_TRACE_IWYU_PREPROCESSOR(
          "File '" << LastIWYUFileEntry->getName() << "' includes file '"
                   << IncludedFile->getName() << "'\n")
    }
  }

  void iwyuTrackMacroUsage(const MacroDefinition &MD, SourceRange SourceRange) {
    llvm::DenseMap<DirectoryEntryRef, ClangRulesetsDirectoryState>::iterator
        DirState;
    const MacroInfo *MI;
    {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(
          this->CI, Timer, this->Timing,
          RulesetIWYUPreprocessorCaptureMacroFileCheckTimer);
      MI = MD.getMacroInfo();
      if (MI == nullptr) {
        return;
      }
      auto UsageFileID = SrcMgr.getFileID(SourceRange.getBegin());
      if (UsageFileID != LastIWYUFileID) {
        LastIWYUFileID = UsageFileID;
        LastIWYUFileEntry = SrcMgr.getFileEntryRefForID(LastIWYUFileID);
      }
      if (!LastIWYUFileEntry) {
        return;
      }
      DirState = this->Dirs.find(LastIWYUFileEntry->getDir());
      if (DirState == this->Dirs.end()) {
        return;
      }
    }
    {
      if (!DirState->second.Materialized) {
        RULESET_TIME_REGION_BEFORE_ANALYSIS(
            this->CI, MaterializationTimer, this->Timing,
            RulesetIWYUPreprocessorCaptureMacroMaterializationTimer);
        this->materializeDirectoryState(DirState->second, CI.getDiagnostics());
      }

      if (DirState->second.EffectiveConfig == nullptr ||
          DirState->second.EffectiveConfig->EffectiveIWYUAnalysis !=
              config::ClangRulesIWYUAnalysis::CRIA_On) {
        return;
      }
    }
    {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(
          this->CI, Timer, this->Timing,
          RulesetIWYUPreprocessorCaptureMacroDependencyInsertTimer);
      auto DefinitionFile =
          SrcMgr.getFileEntryRefForID(SrcMgr.getFileID(MI->getDefinitionLoc()));
      if (!DefinitionFile) {
        return;
      }
      auto &List = IWYUDependencyTree.getOrInsertDefault(*LastIWYUFileEntry);
      List.insert(*DefinitionFile);
      RULESET_TRACE_IWYU_PREPROCESSOR(
          "File '" << LastIWYUFileEntry->getName() << "' uses macro from file '"
                   << DefinitionFile->getName() << "'\n")
    }
  }

  void iwyuTrackSemaUsage(LookupResult &Result) {
    llvm::DenseMap<DirectoryEntryRef, ClangRulesetsDirectoryState>::iterator
        DirState;
    {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(this->CI, Timer, this->Timing,
                                          RulesetIWYUCppCaptureFileCheckTimer);
      auto FileID = SrcMgr.getFileID(SrcMgr.getFileLoc(Result.getNameLoc()));
      if (FileID != LastIWYUFileID) {
        LastIWYUFileID = FileID;
        LastIWYUFileEntry = SrcMgr.getFileEntryRefForID(LastIWYUFileID);
      }
      if (!LastIWYUFileEntry) {
        return;
      }
      DirState = this->Dirs.find(LastIWYUFileEntry->getDir());
      if (DirState == this->Dirs.end()) {
        return;
      }
    }
    {
      if (!DirState->second.Materialized) {
        RULESET_TIME_REGION_BEFORE_ANALYSIS(
            this->CI, MaterializationTimer, this->Timing,
            RulesetIWYUCppCaptureMaterializationTimer);
        this->materializeDirectoryState(DirState->second, CI.getDiagnostics());
      }

      if (DirState->second.EffectiveConfig == nullptr ||
          DirState->second.EffectiveConfig->EffectiveIWYUAnalysis !=
              config::ClangRulesIWYUAnalysis::CRIA_On) {
        return;
      }
    }
    {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(
          this->CI, Timer, this->Timing,
          RulesetIWYUCppCaptureDependencyInsertTimer);
      auto UsageFile = LastIWYUFileEntry;
      llvm::DenseSet<FileEntryRef> *DepList = nullptr;
      for (const auto &Dest : Result) {
        if (Dest == nullptr) {
          continue;
        }
        auto DestEntry = SrcMgr.getFileEntryRefForID(
            SrcMgr.getFileID(SrcMgr.getFileLoc(Dest->getLocation())));
        if (DestEntry) {
          if (DepList == nullptr) {
            DepList = &IWYUDependencyTree.getOrInsertDefault(*UsageFile);
          }
#if RULESET_ENABLE_TRACING_IWYU
          if (!DepList->contains(*DestEntry)) {
            RULESET_TRACE_IWYU("C++ sema dependency: '"
                               << UsageFile->getName() << "' depends on '"
                               << DestEntry->getName() << "'\n")
          }
#endif
          DepList->insert(*DestEntry);
        }
      }
    }
  }

  void iwyuTrackSemaUsage(LookupResult &Result, Scope *Scope) {
    iwyuTrackSemaUsage(Result);
  }

  void iwyuTrackSemaUsage(LookupResult &Result, DeclContext *LookupCtx) {
    iwyuTrackSemaUsage(Result);
  }

private:
  void collectIWYUDependents(FileEntryRef CurrentFile,
                             llvm::DenseSet<FileEntryRef> &Dependents,
                             llvm::sys::SmartMutex<true> &Mutex) {
    Dependents.insert(CurrentFile);
    auto ImmediateDependents = IWYUDependencyTree.find(CurrentFile);
    if (ImmediateDependents != IWYUDependencyTree.end()) {
      for (const auto &Dependent : ImmediateDependents->getSecond()) {
        if (!Dependents.contains(Dependent)) {
          collectIWYUDependents(Dependent, Dependents, Mutex);
        }
      }
    }
  }

  config::ClangRulesIWYUAnalysis
  evaluateIWYUAnalysis(FileEntryRef CurrentFile) {
    auto DirState = Dirs.find(CurrentFile.getDir());
    if (DirState != Dirs.end()) {
      if (!DirState->second.Materialized) {
        // @note: Any file that does not have a materialized state at this point
        // has no .clang-rules file anywhere in it's hierarchy (because
        // otherwise the top-level decl iteration would have found it), and
        // therefore we don't need to run IWYU analysis on that file.
        return config::ClangRulesIWYUAnalysis::CRIA_Off;
      }
      if (DirState->second.EffectiveConfig != nullptr) {
        auto &IWYUAnalysis =
            DirState->second.EffectiveConfig->EffectiveIWYUAnalysis;
        if (IWYUAnalysis != config::ClangRulesIWYUAnalysis::CRIA_NotSet) {
          return IWYUAnalysis;
        }
      }
    }
    return config::ClangRulesIWYUAnalysis::CRIA_Off;
  }

  void emitUnusedInclude(FileEntryRef CurrentFile, SourceLocation SourceLoc,
                         llvm::sys::SmartMutex<true> &Mutex, ASTContext &AST) {
    Mutex.lock();
    AST.getDiagnostics().Report(SourceLoc,
                                diag::warn_iwyu_remove_unused_header);
    Mutex.unlock();
  }

  void emitIndirectDependencyRecommendation(FileEntryRef CurrentFile,
                                            FileEntryRef TargetFile,
                                            SourceLocation SourceLoc,
                                            llvm::sys::SmartMutex<true> &Mutex,
                                            ASTContext &AST) {
    Mutex.lock();
    llvm::SmallString<256> TargetRelativePath(TargetFile.getName());
    llvm::sys::path::remove_dots(TargetRelativePath, true);
    AST.getDiagnostics().Report(SourceLoc,
                                diag::warn_iwyu_replace_unused_header)
        << TargetRelativePath;
    Mutex.unlock();
  }

  bool
  isDependencyReachedThroughFile(FileEntryRef CurrentFile,
                                 FileEntryRef Dependency,
                                 llvm::DenseSet<FileEntryRef> &VisitedFiles) {
    VisitedFiles.insert(CurrentFile);
    if (CurrentFile == Dependency) {
      return true;
    }
    auto ImmediateIncludes = IWYUIncludeTree.find(CurrentFile);
    if (ImmediateIncludes != IWYUIncludeTree.end()) {
      for (const auto &Include : ImmediateIncludes->second) {
        if (VisitedFiles.contains(Include.first)) {
          continue;
        }
        if (isDependencyReachedThroughFile(Include.first, Dependency,
                                           VisitedFiles)) {
          return true;
        }
      }
    }
    return false;
  }

  void analyseFileForIWYU(FileEntryRef CurrentFile,
                          llvm::sys::SmartMutex<true> &Mutex, ASTContext &AST) {
    RULESET_TRACE_IWYU_MUTEX(Mutex, "Analysing file '"
                                        << CurrentFile.getName()
                                        << "' for IWYU diagnostics.\n")
    // Figure out whether we should perform IWYU analysis for the current file,
    // and skip it if we shouldn't.
    config::ClangRulesIWYUAnalysis EvaluatedIWYUAnalysis =
        evaluateIWYUAnalysis(CurrentFile);
    if (EvaluatedIWYUAnalysis == config::ClangRulesIWYUAnalysis::CRIA_Off) {
      RULESET_TRACE_IWYU_MUTEX(
          Mutex, "Skipping file '"
                     << CurrentFile.getName()
                     << "' because IWYU analysis is turned off.\n")
      return;
    }

    // Get our immediate includes and dependencies.
    auto ImmediateIncludes = IWYUIncludeTree.find(CurrentFile);
    auto Dependencies = IWYUDependencyTree.find(CurrentFile);
    if (ImmediateIncludes == IWYUIncludeTree.end()) {
      // We don't include anything, so no analysis needs to be performed.
      return;
    }
    bool HasAnyDependencies = Dependencies != IWYUDependencyTree.end();

    // Track files that we depend on that are immediately included.
    llvm::DenseSet<FileEntryRef> ImmediatelyUsedDependents;

    // Track files that we include but don't have an immediate dependency on.
    llvm::DenseMap<FileEntryRef, SourceLocation> IncludesNotDependedOn;

    // For each include, see what isn't in the immediate dependency list.
    RULESET_TRACE_IWYU_MUTEX(Mutex, "IWYU analysis: Begin '"
                                        << CurrentFile.getName() << "'\n")
    if (ImmediateIncludes != IWYUIncludeTree.end()) {
      for (const auto &Include : ImmediateIncludes->second) {
        if (!HasAnyDependencies ||
            !Dependencies->second.contains(Include.first)) {
          IncludesNotDependedOn.try_emplace(Include.first, Include.second);
        } else {
          ImmediatelyUsedDependents.insert(Include.first);
        }
      }
    }

    // If we don't have any #includes that aren't yet depended on,
    // analysis is finished.
    if (IncludesNotDependedOn.size() == 0) {
      return;
    }

    // Search our dependencies to find out which ones aren't directly included
    // but are being satisifed transitively via another include, and then mark
    // those includes as dependent on. We don't yet emit recommendations of a
    // more narrow include, as this can be highly subjective depending on the
    // context. Instead, we aim to just find includes that are completely
    // unused.
    if (HasAnyDependencies) {
      for (const auto &Dependency : Dependencies->second) {
        if (!ImmediatelyUsedDependents.contains(Dependency)) {
          llvm::DenseSet<FileEntryRef> VisitedIncludes;
          for (const auto &Include : IncludesNotDependedOn) {
            if (isDependencyReachedThroughFile(Include.first, Dependency,
                                               VisitedIncludes)) {
              IncludesNotDependedOn.erase(Include.first);
              break;
            }
          }
        }
      }
    }

    // For any includes that are completely unused, emit diagnostics for them
    // now.
    for (const auto &Include : IncludesNotDependedOn) {
      emitUnusedInclude(CurrentFile, Include.second, Mutex, AST);
    }
  }

public:
  std::unique_ptr<std::vector<config::ClangRules>>
  loadClangRulesFromPreprocessor(clang::FileID &FileID) {
    // Set up our YAML parser.
    SourceMgrAdapter SMAdapter(
        SrcMgr, SrcMgr.getDiagnostics(), diag::err_clangrules_message,
        diag::warn_clangrules_message, diag::note_clangrules_message,
        SrcMgr.getFileEntryRefForID(FileID));
    llvm::yaml::Input YamlParse(SrcMgr.getBufferData(FileID), nullptr,
                                SMAdapter.getDiagHandler(),
                                SMAdapter.getDiagContext());

    // Parse all of the YAML documents, with each one being a ClangRules
    // configuration. This allows developers to put multiple namespaced
    // rules/ruleset documents into a single YAML file.
    std::unique_ptr<std::vector<config::ClangRules>> LoadedDocuments =
        std::make_unique<std::vector<config::ClangRules>>();
    YamlParse >> *LoadedDocuments;
    if (YamlParse.error()) {
      return nullptr;
    }

    // Track whether the rules in all the documents are still valid.
    bool StillValid = true;

    // Iterate through all of the documents and load them.
    for (auto &Document : *LoadedDocuments) {
      // Go through rules, make sure they aren't already prefixed, and then
      // update our in-memory version of the rules file to prefix them with the
      // namespace.
      for (auto &Rule : Document.Rules) {
        if (Rule.Name.find('/') != std::string::npos) {
          SrcMgr.getDiagnostics().Report(
              SrcMgr.getLocForStartOfFile(FileID),
              diag::err_clangrules_rule_name_is_prefixed)
              << Rule.Name;
          StillValid = false;
          continue;
        }
        std::string NamespacedName = Document.Namespace;
        NamespacedName.append("/");
        NamespacedName.append(Rule.Name);
        Rule.Name = NamespacedName;

        // Make sure this namespaced rule name isn't already taken.
        if (this->RuleByNamespacedName[Rule.Name] != nullptr) {
          SrcMgr.getDiagnostics().Report(
              SrcMgr.getLocForStartOfFile(FileID),
              diag::err_clangrules_rule_name_conflict)
              << Rule.Name;
          StillValid = false;
          continue;
        }

        // Attempt to parse the matcher expression.
        {
          clang::ast_matchers::dynamic::Diagnostics ParseDiag;
          llvm::StringRef MatcherRef(Rule.Matcher);
          Rule.MatcherParsed =
              clang::ast_matchers::dynamic::Parser::parseMatcherExpression(
                  MatcherRef, &ParseDiag);
          if (!Rule.MatcherParsed.has_value()) {
            SrcMgr.getDiagnostics().Report(
                SrcMgr.getLocForStartOfFile(FileID),
                diag::err_clangrules_rule_matcher_parse_failure)
                << NamespacedName << ParseDiag.toStringFull();
            StillValid = false;
            continue;
          }
          if (Rule.TraversalMode == config::ClangRulesTraversalMode::
                                        CRTM_IgnoreUnlessSpelledInSource) {
            Rule.MatcherParsed = Rule.MatcherParsed.value().withTraversalKind(
                clang::TraversalKind::TK_IgnoreUnlessSpelledInSource);
          } else {
            // @note: We assume that TraversalKind::TK_AsIs will remain the
            // default internally inside Clang and thus we don't need to modify
            // MatcherParsed in this case.
          }
        }
      }

      // Go through rulesets and namespace both their name and any unprefixed
      // rules they enable, and normalize the severity on rules using the
      // default severity if it's not set.
      for (auto &Ruleset : Document.Rulesets) {
        if (Ruleset.Name.find('/') != std::string::npos) {
          SrcMgr.getDiagnostics().Report(
              SrcMgr.getLocForStartOfFile(FileID),
              diag::err_clangrules_ruleset_name_is_prefixed)
              << Ruleset.Name;
          StillValid = false;
        } else {
          std::string NamespacedName = Document.Namespace;
          NamespacedName.append("/");
          NamespacedName.append(Ruleset.Name);
          Ruleset.Name = NamespacedName;
        }

        // Make sure this namespaced ruleset name isn't already taken.
        if (this->RulesetByNamespacedName[Ruleset.Name] != nullptr) {
          SrcMgr.getDiagnostics().Report(
              SrcMgr.getLocForStartOfFile(FileID),
              diag::err_clangrules_rule_name_conflict)
              << Ruleset.Name;
          StillValid = false;
          continue;
        }

        // Prevent the ruleset severity from being explicitly set as 'NotSet'.
        if (Ruleset.Severity ==
            clang::rulesets::config::ClangRulesSeverity::CRS_NotSet) {
          SrcMgr.getDiagnostics().Report(
              SrcMgr.getLocForStartOfFile(FileID),
              diag::err_clangrules_ruleset_severity_is_notset)
              << Ruleset.Name;
          StillValid = false;
        }

        // Namespace all of the rule entries and set the severity of the rule to
        // that of the ruleset if the rule doesn't explicitly set a severity.
        for (auto &Rule : Ruleset.Rules) {
          if (Rule.Name.find('/') == std::string::npos) {
            std::string NamespacedName = Document.Namespace;
            NamespacedName.append("/");
            NamespacedName.append(Rule.Name);
            Rule.Name = NamespacedName;
          }
          if (Rule.Severity ==
              clang::rulesets::config::ClangRulesSeverity::CRS_NotSet) {
            Rule.Severity = Ruleset.Severity;
          }
        }

        // Namespace all of the ruleset entries.
        for (auto &NestedRuleset : Ruleset.Rulesets) {
          if (NestedRuleset.Name.find('/') == std::string::npos) {
            std::string NamespacedName = Document.Namespace;
            NamespacedName.append("/");
            NamespacedName.append(NestedRuleset.Name);
            NestedRuleset.Name = NamespacedName;
          }
        }
      }
    }

    // If we have a fatal error in loading the rules, release the memory
    // and treat the directory as if it has no rules at all.
    if (!StillValid) {
      return nullptr;
    }

    // Map all of the namespaced rule names and ruleset names across all
    // documents to their locations in memory.
    for (auto &Document : *LoadedDocuments) {
      for (auto &Rule : Document.Rules) {
        this->RuleByNamespacedName[Rule.Name] = &Rule;
      }
      for (auto &Ruleset : Document.Rulesets) {
        this->RulesetByNamespacedName[Ruleset.Name] = &Ruleset;
      }
    }

    // Return the loaded rules.
    return LoadedDocuments;
  }

private:
  void
  applyRulesetToEffectiveRules(bool &StillValid,
                               llvm::DenseSet<llvm::StringRef> &VisitedRulesets,
                               const config::ClangRulesRuleset &Ruleset,
                               ClangRulesetsEffectiveConfig *EffectiveConfig,
                               DiagnosticsEngine &DiagEngine) {
    // Have we already visited this ruleset? This prevents recursion loops.
    if (VisitedRulesets.contains(Ruleset.Name)) {
      return;
    }
    VisitedRulesets.insert(Ruleset.Name);

    // Apply the entries in 'Rules'.
    for (const auto &RulesetRule : Ruleset.Rules) {
      // Lookup the rule by namespaced name. If this doesn't exist, then the
      // ruleset is referencing a rule that isn't known.
      auto *Rule = this->RuleByNamespacedName[RulesetRule.Name];
      if (Rule == nullptr) {
        DiagEngine.Report(diag::err_clangrules_rule_missing)
            << Ruleset.Name << RulesetRule.Name;
        StillValid = false;
      } else {
        EffectiveConfig->EffectiveRules[RulesetRule.Name] =
            ClangRulesetsEffectiveRule{Rule, RulesetRule.Severity};
      }
    }

    // Apply the entries in 'Rulesets'.
    for (const auto &RulesetRuleset : Ruleset.Rulesets) {
      // Lookup the ruleset by namespaced name. If this doesn't exist, then the
      // ruleset is referencing a ruleset that isn't known.
      auto *NestedRuleset = this->RulesetByNamespacedName[RulesetRuleset.Name];
      if (NestedRuleset == nullptr) {
        DiagEngine.Report(diag::err_clangrules_rule_missing)
            << Ruleset.Name << RulesetRuleset.Name;
        StillValid = false;
      } else {
        applyRulesetToEffectiveRules(StillValid, VisitedRulesets,
                                     *NestedRuleset, EffectiveConfig,
                                     DiagEngine);
      }
    }
  }

  void materializeDirectoryState(ClangRulesetsDirectoryState &DirState,
                                 DiagnosticsEngine &DiagEngine) {
    assert(!DirState.Materialized);

    // If we have an actual on-disk configuration with at least one ruleset
    // defined, we need to merge that with our parent.
    bool HasConfigsToMerge = DirState.ActualOnDiskConfigs &&
                             DirState.ActualOnDiskConfigs->size() > 0;
    if (HasConfigsToMerge) {
      HasConfigsToMerge = false;
      for (const auto &Document : *DirState.ActualOnDiskConfigs) {
        if (Document.IWYUAnalysis !=
            config::ClangRulesIWYUAnalysis::CRIA_NotSet) {
          HasConfigsToMerge = true;
        }
        if (!HasConfigsToMerge) {
          for (const auto &Ruleset : Document.Rulesets) {
            if (!Ruleset.DefineOnly) {
              HasConfigsToMerge = true;
              break;
            }
          }
        }
      }
    }
    if (HasConfigsToMerge) {
      // Create our new effective configuration.
      auto *EffectiveConfig = new ClangRulesetsEffectiveConfig();

      // Get the materialized effective config of the parent, if we're not
      // a root directory, and then copy from that.
      if (DirState.ParentDirectory) {
        auto &ParentState = this->Dirs[*DirState.ParentDirectory];
        if (!ParentState.Materialized) {
          RULESET_TRACE_CONFIG("Materializing "
                               << DirState.ParentDirectory->getName() << "\n");
          assert(&ParentState != &DirState);
          this->materializeDirectoryState(ParentState, DiagEngine);
          RULESET_TRACE_CONFIG("Materialized "
                               << DirState.ParentDirectory->getName() << "\n");
        }
        if (ParentState.EffectiveConfig != nullptr) {
          // Copy the effective rules (which are namespaced rule names plus the
          // effective severity).
          EffectiveConfig->EffectiveRules =
              ParentState.EffectiveConfig->EffectiveRules;
          EffectiveConfig->EffectiveIWYUAnalysis =
              ParentState.EffectiveConfig->EffectiveIWYUAnalysis;
        }
      }

      // For all of the rulesets in our rules, add them or update their existing
      // severity in the effective rules.
      bool StillValid = true;
      llvm::DenseSet<llvm::StringRef> VisitedRulesets;
      for (const auto &Document : *DirState.ActualOnDiskConfigs) {
        for (const auto &Ruleset : Document.Rulesets) {
          if (Ruleset.DefineOnly) {
            // This ruleset is only being defined here; it should not be made
            // active automatically.
            continue;
          }
          this->applyRulesetToEffectiveRules(StillValid, VisitedRulesets,
                                             Ruleset, EffectiveConfig,
                                             DiagEngine);
        }
        if (Document.IWYUAnalysis !=
            config::ClangRulesIWYUAnalysis::CRIA_NotSet) {
          EffectiveConfig->EffectiveIWYUAnalysis = Document.IWYUAnalysis;
        }
      }
      if (!StillValid) {
        // This directory doesn't have a valid .clang-rules effective state.
        delete EffectiveConfig;
        DirState.Materialized = true;
        DirState.EffectiveConfig = nullptr;
        return;
      }

      // Remove any effective rules that are silence, since we don't need to run
      // them at all.
      for (auto It = EffectiveConfig->EffectiveRules.begin();
           It != EffectiveConfig->EffectiveRules.end();) {
        if (It->second.Severity == config::ClangRulesSeverity::CRS_Silence &&
            !It->second.Rule->Debug) {
          It = EffectiveConfig->EffectiveRules.erase(It);
        } else {
          ++It;
        }
      }

      // Remove any effective rules that are Windows-only if we're not targeting
      // Windows. This allows us to exclude rules that check things like
      // __dllexport.
      if (!CI.getTarget().getTriple().isOSWindows()) {
        for (auto It = EffectiveConfig->EffectiveRules.begin();
             It != EffectiveConfig->EffectiveRules.end();) {
          if (It->second.Rule->WindowsOnly) {
            It = EffectiveConfig->EffectiveRules.erase(It);
          } else {
            ++It;
          }
        }
      }

      // If there are no effective rules remaining, materialize this directory
      // as if there was no .clang-rules anywhere in the hierarchy.
      if (EffectiveConfig->EffectiveRules.size() == 0 &&
          EffectiveConfig->EffectiveIWYUAnalysis ==
              config::ClangRulesIWYUAnalysis::CRIA_NotSet) {
        delete EffectiveConfig;
        DirState.Materialized = true;
        DirState.EffectiveConfig = nullptr;
        return;
      }

      // Otherwise, this is the effective config for this directory.
      this->CreatedEffectiveConfigs.push_back(EffectiveConfig);
      DirState.Materialized = true;
      DirState.EffectiveConfig = EffectiveConfig;
      return;
    }
    // Otherwise, we're going to ask our parent directory to be materialized
    // if they aren't already, and then borrow their materialized values.
    else {
      if (DirState.ParentDirectory) {
        // Materialize our parent if needed and get the config.
        auto &ParentState = this->Dirs[*DirState.ParentDirectory];
        if (!ParentState.Materialized) {
          RULESET_TRACE_CONFIG("Materializing "
                               << DirState.ParentDirectory->getName() << "\n");
          assert(&ParentState != &DirState);
          this->materializeDirectoryState(ParentState, DiagEngine);
          RULESET_TRACE_CONFIG("Materialized "
                               << DirState.ParentDirectory->getName() << "\n");
        }
        DirState.EffectiveConfig = ParentState.EffectiveConfig;
        DirState.Materialized = true;
      } else {
        // No parent directory. We are a root with no on-disk config.
        DirState.EffectiveConfig = nullptr;
        DirState.Materialized = true;
      }
    }
  }

  class InstantiatedMatcher {
  private:
    class InstantiatedMatcherCallback
        : public clang::ast_matchers::MatchFinder::MatchCallback {
    private:
      llvm::sys::SmartMutex<true> &Mutex;
      ASTContext &AST;
      const ClangRulesetsEffectiveRule &EffectiveRule;

    public:
      InstantiatedMatcherCallback(
          llvm::sys::SmartMutex<true> &InMutex, ASTContext &InAST,
          const ClangRulesetsEffectiveRule &InEffectiveRule)
          : Mutex(InMutex), AST(InAST), EffectiveRule(InEffectiveRule){};

      virtual void run(const clang::ast_matchers::MatchFinder::MatchResult
                           &Result) override {
        // Obtain lock.
        this->Mutex.lock();

        // If this rule is configured for debug/diagnostic mode, emit the AST
        // of all bound nodes.
        if (this->EffectiveRule.Rule->Debug) {
          llvm::outs() << "Printing AST matcher diagnostics for rule '"
                       << this->EffectiveRule.Rule->Name
                       << "' as the 'Debug' option is enabled in the "
                          ".clang-rules file where it is defined.\n";
          for (const auto &KV : Result.Nodes.getMap()) {
            llvm::outs() << "The bound node '" << KV.first << "' of rule '"
                         << this->EffectiveRule.Rule->Name
                         << "' matches the AST node:\n";
            KV.second.dump(llvm::outs(), this->AST);
          }

          // Debug rules bypass the 'Silence' check excluding them from
          // evaluation, so that we can still run this "dump AST" code
          // even when they're not meant to generate a diagnostic. If this
          // rule is configured for 'Silence' severity, return now to skip
          // over any diagnostic emit code.
          if (this->EffectiveRule.Severity ==
              config::ClangRulesSeverity::CRS_Silence) {
            // Release lock.
            this->Mutex.unlock();
            // Return early.
            return;
          }
        }

        // Report the diagnostic on the main node.
        {
          clang::SourceLocation CallsiteLoc;
          auto CallsiteIt =
              Result.Nodes.getMap().find(this->EffectiveRule.Rule->Callsite);
          if (CallsiteIt == Result.Nodes.getMap().end()) {
            CallsiteLoc = this->AST.getTranslationUnitDecl()->getBeginLoc();
          } else {
            CallsiteLoc = CallsiteIt->second.getSourceRange().getBegin();
          }

          clang::DiagnosticIDs::Level DiagnosticLevel =
              convertDiagnosticLevel(this->EffectiveRule.Severity);
          auto CallsiteDiagID =
              this->AST.getDiagnostics().getDiagnosticIDs()->getCustomDiagID(
                  DiagnosticLevel, this->EffectiveRule.Rule->ErrorMessage);
          this->AST.getDiagnostics().Report(CallsiteLoc, CallsiteDiagID);
        }

        // Report any additional hints if they're present.
        for (const auto &HintKV : this->EffectiveRule.Rule->Hints) {
          auto HintIt = Result.Nodes.getMap().find(HintKV.first);
          if (HintIt != Result.Nodes.getMap().end()) {
            clang::SourceLocation HintLoc =
                HintIt->second.getSourceRange().getBegin();

            auto HintDiagID =
                this->AST.getDiagnostics().getDiagnosticIDs()->getCustomDiagID(
                    clang::DiagnosticIDs::Note, HintKV.second);
            this->AST.getDiagnostics().Report(HintLoc, HintDiagID);
          }
        }

        // Release lock.
        this->Mutex.unlock();
      }
    };

    std::unique_ptr<ast_matchers::MatchFinder> Finder;
    llvm::DenseMap<const ClangRulesetsEffectiveRule *,
                   clang::ast_matchers::MatchFinder::MatchCallback *>
        Callbacks;
    llvm::sys::SmartMutex<true> &Mutex;
    ASTContext &AST;

  public:
    InstantiatedMatcher(llvm::sys::SmartMutex<true> &InMutex, ASTContext &InAST)
        : Finder(std::make_unique<ast_matchers::MatchFinder>()), Callbacks(),
          Mutex(InMutex), AST(InAST) {}
    InstantiatedMatcher(const InstantiatedMatcher &) = delete;
    InstantiatedMatcher(InstantiatedMatcher &&) = delete;
    ~InstantiatedMatcher() {
      for (const auto &KV : this->Callbacks) {
        delete KV.second;
      }
    }

    void addRule(const ClangRulesetsEffectiveRule &EffectiveRule) {
      if (this->Callbacks.contains(&EffectiveRule)) {
        return;
      }
      auto &Rule = EffectiveRule.Rule;
      if (Rule->MatcherParsed.has_value()) {
        auto *Callback = new InstantiatedMatcherCallback(this->Mutex, this->AST,
                                                         EffectiveRule);
        RULESET_TRACE_RULESET("Adding dynamic matcher to finder.\n");
        this->Finder->addDynamicMatcher(*Rule->MatcherParsed, Callback);
        this->Callbacks[&EffectiveRule] = Callback;
      }
    }

    void match(const OptionalFileEntryRef &FileEntry, clang::Decl *Decl) {
      RULESET_TRACE_RULESET_MUTEX_WITH_DECL_DUMP(
          Mutex, Decl,
          "Calling matchDecl for declaration in file '"
              << (FileEntry.has_value() ? FileEntry->getName() : "") << "':\n");
      this->Finder->matchDecl(Decl, this->AST);
    }
  };

public:
  void runAnalysisOnTranslationUnit(ASTContext &AST) {
    RULESET_TIME_REGION_ANALYSIS(this->CI, Timer, this->Timing);

    const auto *UnitDeclEntry = AST.getTranslationUnitDecl();
    if (UnitDeclEntry == nullptr) {
      RULESET_TRACE_CORE(
          "Skipping AST analysis because there is no translation unit.\n");
      return;
    }
    const SourceManager &SrcMgr = AST.getSourceManager();

    RULESET_TRACE_CORE("Starting AST analysis.\n");

    // Track the current file ID and current effective config, so that as we go
    // over decls in the same source file, we don't need to redo lookups.
    FileID CurrentFileID;
    OptionalFileEntryRef CurrentFileEntry;
    ClangRulesetsEffectiveConfig *CurrentEffectiveConfig = nullptr;

    // Cached callbacks.
    std::map<ClangRulesetsEffectiveConfig *, InstantiatedMatcher *>
        SharedEffectiveConfigToInstantiatedMatchers;

    // Set up our mutex and thread pool.
    llvm::sys::SmartMutex<true> ThreadMutex;
    llvm::ThreadPool ThreadPool;

    // Track a list of files that we'll run IWYU analysis on.
    llvm::DenseSet<FileEntryRef> IWYUAnalysisFiles;

    RULESET_TRACE_IWYU("IWYU preprocessor dependency: Tracking "
                       << IWYUDependencyTree.size()
                       << " keys in dependency tree, " << IWYUIncludeTree.size()
                       << " keys in include tree.\n")

#if RULESET_ENABLE_TRACING_CONTEXT
    int TotalDecls = 0;
    for (const auto &DeclEntry : UnitDeclEntry->decls()) {
      TotalDecls++;
    }
#endif

    // Iterate through all of the decls in the translation unit.
#if RULESET_ENABLE_TRACING_CONTEXT
    int CurrentDecl = 0;
#endif
    for (const auto &DeclEntry : UnitDeclEntry->decls()) {
#if RULESET_ENABLE_TRACING_CONTEXT
      CurrentDecl++;
#endif
      bool FileChanged = false;
      {
        RULESET_TIME_REGION_DURING_ANALYSIS(this->CI, FileCheckTimer,
                                            this->Timing,
                                            RulesetAnalysisFileCheckTimer);

        // Get the location of this decl.
        FileID NewFileID =
            SrcMgr.getFileID(SrcMgr.getFileLoc(DeclEntry->getLocation()));
        if (NewFileID.isInvalid()) {
          // Ignore any decls that have no file ID.
          RULESET_TRACE_CONTEXT(CurrentDecl
                                << "/" << TotalDecls
                                << ": Has no file ID for location.\n");
          continue;
        }

        // If we're not in the same file as we were previously...
        FileChanged = (NewFileID != CurrentFileID);
        if (FileChanged) {
          // @note: We always update CurrentFileID, even if the calls below are
          // unable to get valid info. This allows us to skip over decls quickly
          // if we know the last file ID won't actually resolve anywhere.
          CurrentFileID = NewFileID;
          CurrentEffectiveConfig = nullptr;
        }
      }

      if (FileChanged) {
        RULESET_TIME_REGION_DURING_ANALYSIS(this->CI, FileChangeTimer,
                                            this->Timing,
                                            RulesetAnalysisFileChangeTimer);

        // Try to get the file entry for the file ID.
        auto FileEntry = SrcMgr.getFileEntryRefForID(CurrentFileID);
        if (!FileEntry) {
          // This is an unknown file - no rules apply.
          RULESET_TRACE_CONTEXT(
              CurrentDecl << "/" << TotalDecls
                          << ": Has no file entry for current file ID.\n");
          continue;
        }

        RULESET_TRACE_CONTEXT(
            CurrentDecl << "/" << TotalDecls << ": Current file changed to '"
                        << FileEntry->getName() << "' for decl '"
                        << DeclEntry->getDeclKindName() << "' at "
                        << DeclEntry->getLocation().printToString(SrcMgr)
                        << "\n");

        // Get the effective configuration that should now apply.
        auto DirState = this->Dirs.find(FileEntry->getDir());
        if (DirState == this->Dirs.end()) {
          // This is not a tracked directory - no rules apply.
          continue;
        }

        // Materialize this directory if needed.
        if (!DirState->second.Materialized) {
          RULESET_TIME_REGION_DURING_ANALYSIS_NESTED(
              this->CI, MaterializationTimer, this->Timing,
              RulesetAnalysisFileChangeTimer,
              RulesetAnalysisMaterializationTimer);
          this->materializeDirectoryState(DirState->second,
                                          AST.getDiagnostics());
        }

        // Set effective configuration.
        CurrentFileEntry = FileEntry;
        CurrentEffectiveConfig = DirState->second.EffectiveConfig;

        // If there is a config, instantiate the matcher we will use.
        if (CurrentEffectiveConfig != nullptr) {
          auto Matcher = new InstantiatedMatcher(ThreadMutex,
                                                 const_cast<ASTContext &>(AST));
          for (const auto &EffectiveRule :
               CurrentEffectiveConfig->EffectiveRules) {
            RULESET_TRACE_MATCHER(
                "Adding rule to matcher: " << EffectiveRule.first << "\n");
            Matcher->addRule(EffectiveRule.second);
          }
          RULESET_TRACE_MATCHER("Instantiated matcher.\n");
          SharedEffectiveConfigToInstantiatedMatchers[CurrentEffectiveConfig] =
              Matcher;

          if (CurrentEffectiveConfig->EffectiveIWYUAnalysis ==
              config::ClangRulesIWYUAnalysis::CRIA_On) {
            IWYUAnalysisFiles.insert(*FileEntry);
          }
        }
      } else {
        RULESET_TRACE_CONTEXT(CurrentDecl
                              << "/" << TotalDecls
                              << ": File remaining same for decl '"
                              << DeclEntry->getDeclKindName() << "' at "
                              << DeclEntry->getLocation().printToString(SrcMgr)
                              << "\n");
      }

#if !RULESET_SKIP_ALL_ANALYSIS
      // Only run matchers if this declaration has an effective config
      // associated with it.
      InstantiatedMatcher *Matcher =
          SharedEffectiveConfigToInstantiatedMatchers[CurrentEffectiveConfig];
      if (CurrentEffectiveConfig != nullptr) {
        // Evaluate all of the matchers against this node.
        if (this->ThreadingEnabled) {
          RULESET_TIME_REGION_DURING_ANALYSIS(this->CI, ScheduleTimer,
                                              this->Timing,
                                              RulesetAnalysisScheduleTimer);
          ThreadPool.async(
              [](OptionalFileEntryRef *OptionalFileEntryRef, Decl *DeclEntry,
                 InstantiatedMatcher *Matcher) {
                Matcher->match(*OptionalFileEntryRef, DeclEntry);
              },
              &CurrentFileEntry, DeclEntry, Matcher);
        } else {
          RULESET_TIME_REGION_DURING_ANALYSIS(this->CI, ExecuteTimer,
                                              this->Timing,
                                              RulesetAnalysisExecuteTimer);
          Matcher->match(CurrentFileEntry, DeclEntry);
        }
      }
#endif
    }

#if !RULESET_SKIP_ALL_ANALYSIS
    // Run IWYU analysis in parallel across the files that have IWYU analysis
    // enabled.
    if (IWYUAnalysisFiles.size() > 0) {
      RULESET_TIME_REGION_DURING_ANALYSIS(this->CI, WaitTimer, this->Timing,
                                          RulesetIWYUAnalysisTimer);

      // Schedule or run IWYU analysis.
      for (const auto &AnalysisFile : IWYUAnalysisFiles) {
        if (this->ThreadingEnabled) {
          ThreadPool.async(
              [this](FileEntryRef AnalysisFile,
                     llvm::sys::SmartMutex<true> *ThreadMutex,
                     ASTContext *AST) {
                this->analyseFileForIWYU(AnalysisFile, *ThreadMutex, *AST);
              },
              AnalysisFile, &ThreadMutex, &AST);
        } else {
          analyseFileForIWYU(AnalysisFile, ThreadMutex, AST);
        }
      }
    }
#endif

    // Wait for matchers to run in threads.
    if (this->ThreadingEnabled) {
      RULESET_TIME_REGION_DURING_ANALYSIS(this->CI, WaitTimer, this->Timing,
                                          RulesetAnalysisWaitTimer);
      ThreadPool.wait();
    }

    // Free all the matchers.
    for (const auto &KV : SharedEffectiveConfigToInstantiatedMatchers) {
      delete KV.second;
    }
    SharedEffectiveConfigToInstantiatedMatchers.clear();

    RULESET_TRACE_CORE("Ending AST analysis.\n");
  }
};

class ClangRulesetsPPCallbacks : public PPCallbacks {
private:
  std::shared_ptr<ClangRulesetsState> State;
  CompilerInstance &CI;

public:
  ClangRulesetsPPCallbacks(std::shared_ptr<ClangRulesetsState> InState,
                           CompilerInstance &InCI)
      : State(InState), CI(InCI){};
  virtual ~ClangRulesetsPPCallbacks() override = default;

  virtual void LexedFileChanged(FileID FID, LexedFileChangeReason Reason,
                                SrcMgr::CharacteristicKind FileType,
                                FileID PrevFID, SourceLocation Loc) override {
    SourceManager &SrcMgr = CI.getSourceManager();
    OptionalFileEntryRef OptionalFileEntryRef =
        SrcMgr.getFileEntryRefForID(FID);
    if (!OptionalFileEntryRef.has_value()) {
      // If there's no file entry for the new file, we don't process it.
      return;
    }

    DirectoryEntryRef ContainingDirectory = OptionalFileEntryRef->getDir();
    if (!State->Dirs.contains(ContainingDirectory)) {
      RULESET_TIME_REGION_BEFORE_ANALYSIS(this->CI, Timer,
                                          this->State->getTiming(),
                                          RulesetLoadClangRulesTimer);

      // This leaf directory hasn't been seen before. We need to make an
      // absolute path with '.' entries removed so that we can start
      // traversing up the directory tree.
      llvm::SmallString<256> LeafAbsolutePath(ContainingDirectory.getName());
      CI.getFileManager().makeAbsolutePath(LeafAbsolutePath);
      llvm::sys::path::remove_dots(LeafAbsolutePath, true);

      // Track our current absolute path as we move upwards from the leaf.
      llvm::StringRef CurrentAbsolutePath = LeafAbsolutePath;

      // Starting at the current directory, search upwards for .clang-rules
      // files.
      while (!State->Dirs.contains(ContainingDirectory)) {
        // Convert to an absolute path, since we might need to traverse up out
        // of the working directory to find our .clangrules files.
        // Go check this directory for a .clangrules file.
        llvm::SmallString<256> ClangRulesPath(CurrentAbsolutePath);
        llvm::sys::path::append(ClangRulesPath, ".clang-rules");
        llvm::Expected<FileEntryRef> ClangRulesFile =
            CI.getFileManager().getFileRef(ClangRulesPath, true, true);
        if (ClangRulesFile) {
          // We got a .clangrules file in this directory; load it into the
          // Clang source manager so we can report diagnostics etc.
          clang::FileID ClangRulesFileID =
              CI.getSourceManager().getOrCreateFileID(
                  ClangRulesFile.get(), SrcMgr::CharacteristicKind::C_User);
          State->Dirs[ContainingDirectory].ActualOnDiskConfigs =
              State->loadClangRulesFromPreprocessor(ClangRulesFileID);

          // Add the .clang-rules to the dependencies so that external tools
          // such as UBT know to build again when the rules file changes.
          //
          // @note: It's impossible for us to notify external tools of paths
          // that *might* influence compilation if a new .clang-rules file is
          // added to the folder hierarchy, since UBT assumes all dependencies
          // are files that exist (so we can't even emit the directory whose
          // last modified time would change when a file is added or deleted).
          CI.getDependencyOutputOpts().ExtraDeps.push_back(
              std::pair<std::string, ExtraDepKind>(
                  ClangRulesPath, ExtraDepKind::EDK_DepFileEntry));
        } else {
          // We did not get a .clangrules file in this directory; cache that
          // it is empty.
          consumeError(ClangRulesFile.takeError());
          State->Dirs[ContainingDirectory].ActualOnDiskConfigs = nullptr;
        }
        // Modify CurrentAbsolutePath so that it contains the next parent path
        // to evaluate.
        RULESET_TRACE_CONFIG("Computed parent directory of '"
                             << CurrentAbsolutePath);
        CurrentAbsolutePath = llvm::sys::path::parent_path(CurrentAbsolutePath);
        RULESET_TRACE_CONFIG_NO_PREFIX("' as '" << CurrentAbsolutePath
                                                << "'\n");
        if (CurrentAbsolutePath.empty() ||
            (llvm::sys::path::is_style_windows(
                 llvm::sys::path::Style::native) &&
             CurrentAbsolutePath.ends_with(":"))) {
          // No further parent directories.
          break;
        } else {
          llvm::Expected<DirectoryEntryRef> OptionalParentDirectory =
              CI.getFileManager().getDirectoryRef(CurrentAbsolutePath, true);
          if (!OptionalParentDirectory) {
            // Can't get parent directory.
            break;
          } else {
            // Loop again with the new parent directory.
            State->Dirs[ContainingDirectory].ParentDirectory =
                OptionalParentDirectory.get();
            ContainingDirectory = OptionalParentDirectory.get();
          }
        }
      }
    }
  }

  virtual void InclusionDirective(SourceLocation HashLoc,
                                  const Token &IncludeTok, StringRef FileName,
                                  bool IsAngled, CharSourceRange FilenameRange,
                                  OptionalFileEntryRef File,
                                  StringRef SearchPath, StringRef RelativePath,
                                  const Module *Imported,
                                  SrcMgr::CharacteristicKind FileType) {
    State->iwyuTrackInclusionDirective(HashLoc, File);
  }

  virtual void MacroExpands(const Token &MacroNameTok,
                            const MacroDefinition &MD, SourceRange Range,
                            const MacroArgs *Args) {
    State->iwyuTrackMacroUsage(MD, Range);
  }

  virtual void SemaSuccessfulLookup(LookupResult &R, Scope *S) {
    State->iwyuTrackSemaUsage(R, S);
  }

  virtual void SemaSuccessfulLookup(LookupResult &R, DeclContext *DC) {
    State->iwyuTrackSemaUsage(R, DC);
  }
};

class ClangRulesetsConsumer : public ASTConsumer {
private:
  std::shared_ptr<ClangRulesetsState> State;

public:
  ClangRulesetsConsumer(std::shared_ptr<ClangRulesetsState> InState)
      : State(InState){};
  virtual ~ClangRulesetsConsumer() override = default;

  void HandleTranslationUnit(ASTContext &AST) override {
    RULESET_TRACE_CORE("Receiving translation unit for analysis\n");
    this->State->runAnalysisOnTranslationUnit(AST);
  }
};

std::unique_ptr<ASTConsumer>
ClangRulesetsProvider::CreateASTConsumer(clang::CompilerInstance &CI) {
  bool ThreadingEnabled = false;
#if defined(_WIN32)
  HMODULE DetoursHandle = GetModuleHandleW(L"UbaDetours.dll");
  if (DetoursHandle) {
    // UBA does not like it when Clang suddenly starts doing multi-threaded
    // work, so turn threading off in these cases. The performance hit is
    // probably acceptable given this scenario means the build is being
    // distributed onto remote machines.
    RULESET_TRACE_CORE("Turning off multi-threading, detected UBA!\n");
    ThreadingEnabled = false;
  }
#endif

  // Create our state that will be shared across consumers and the
  // preprocessor.
  RULESET_TRACE_CORE("Creating Clang rulesets state\n");
  std::shared_ptr<ClangRulesetsState> State =
      std::make_shared<ClangRulesetsState>(ThreadingEnabled, CI);

  // Register our preprocessor callbacks, which are used to discover rulesets
  // as files are included.
  CI.getPreprocessor().addPPCallbacks(
      std::make_unique<ClangRulesetsPPCallbacks>(State, CI));

  // Create and return our consumer for performing analysis.
  return std::make_unique<ClangRulesetsConsumer>(State);
}

} // namespace clang::rulesets