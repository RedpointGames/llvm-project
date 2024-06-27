#include "ClangRulesets.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/Dynamic/Parser.h"
#include "clang/Basic/SourceMgrAdapter.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/Support/Mutex.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"

using namespace clang;

#define RULESET_ENABLE_TIMING 0
#define RULESET_ENABLE_TIMING_ALWAYS 0
#define RULESET_ENABLE_THREADING 1
#define RULESET_ENABLE_TRACING 0

#if RULESET_ENABLE_TRACING
#define RULESET_TRACE(x) llvm::errs() << x;
#else
#define RULESET_TRACE(x)
#endif

#if RULESET_ENABLE_TIMING
#if RULESET_ENABLE_TIMING_ALWAYS
#define RULESET_TIME_REGION(CI, Name, Timing, Timer)                           \
  llvm::TimeRegion Name((Timing) == nullptr ? nullptr : ((Timing)->Timer.get()))
#else
#define RULESET_TIME_REGION(CI, Name, Timing, Timer)                           \
  llvm::TimeRegion Name(                                                       \
      (!(CI).hasFrontendTimer())                                               \
          ? nullptr                                                            \
          : ((Timing) == nullptr ? nullptr : ((Timing)->Timer.get())))
#endif
#else
#define RULESET_TIME_REGION(CI, Name, Timing, Timer)
#endif

namespace clang::rulesets::config {

enum ClangRulesSeverity : int8_t {
  CRS_NotSet,
  CRS_Silence,
  CRS_Info,
  CRS_Warning,
  CRS_Error,
};

struct ClangRulesRule {
  std::string Name;
  std::string Matcher;
  std::string ErrorMessage;
  std::string Callsite;
  std::map<std::string, std::string> Hints;
  std::optional<clang::ast_matchers::internal::DynTypedMatcher> MatcherParsed;
  bool WindowsOnly;
};

struct ClangRulesRulesetRule {
  std::string Name;
  ClangRulesSeverity Severity;
};

struct ClangRulesRuleset {
  std::string Name;
  ClangRulesSeverity Severity;
  std::vector<ClangRulesRulesetRule> Rules;
};

struct ClangRules {
  std::string Namespace;
  std::vector<ClangRulesRule> Rules;
  std::vector<ClangRulesRuleset> Rulesets;
};

} // namespace clang::rulesets::config

LLVM_YAML_IS_STRING_MAP(std::string);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRulesetRule);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRule);
LLVM_YAML_IS_SEQUENCE_VECTOR(clang::rulesets::config::ClangRulesRuleset);

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

template <> struct MappingTraits<clang::rulesets::config::ClangRulesRule> {
  static void mapping(IO &IO, clang::rulesets::config::ClangRulesRule &Rule) {
    IO.mapRequired("Name", Rule.Name);
    IO.mapRequired("Matcher", Rule.Matcher);
    IO.mapRequired("ErrorMessage", Rule.ErrorMessage);
    IO.mapRequired("Callsite", Rule.Callsite);
    IO.mapOptional("Hints", Rule.Hints);
    IO.mapOptional("WindowsOnly", Rule.WindowsOnly, false);
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

template <> struct MappingTraits<clang::rulesets::config::ClangRulesRuleset> {
  static void mapping(IO &IO,
                      clang::rulesets::config::ClangRulesRuleset &Ruleset) {
    IO.mapRequired("Name", Ruleset.Name);
    IO.mapOptional("Severity", Ruleset.Severity,
                   clang::rulesets::config::ClangRulesSeverity::CRS_Warning);
    IO.mapRequired("Rules", Ruleset.Rules);
  }
};

template <> struct MappingTraits<clang::rulesets::config::ClangRules> {
  static void mapping(IO &IO, clang::rulesets::config::ClangRules &Rules) {
    IO.mapRequired("Namespace", Rules.Namespace);
    IO.mapOptional("Rulesets", Rules.Rulesets);
    IO.mapOptional("Rules", Rules.Rules);
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
};

struct ClangRulesetsDirectoryState {
public:
  // If this directory contained a .clang-rules file, this is the on-disk
  // configuration that was loaded.
  std::unique_ptr<config::ClangRules> ActualOnDiskConfig;
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
  std::unique_ptr<llvm::Timer> RulesetAnalysisTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisFileCheckTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisFileChangeTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisMaterializationTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisExecuteTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisScheduleTimer;
  std::unique_ptr<llvm::Timer> RulesetAnalysisWaitTimer;

  ClangRulesetsTiming()
      : RulesetTimerGroup(std::make_unique<llvm::TimerGroup>(
            "ruleset", "Clang ruleset analysis")),
        RulesetLoadClangRulesTimer(std::make_unique<llvm::Timer>(
            "ruleset-load", "Load .clang-rules files during preprocessor",
            *RulesetTimerGroup)),
        RulesetAnalysisTimer(std::make_unique<llvm::Timer>(
            "ruleset-analysis", "Full time spent in ruleset analysis",
            *RulesetTimerGroup)),
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
            *RulesetTimerGroup)) {}
#endif
};

class ClangRulesetsState {
private:
  clang::CompilerInstance &CI;

public:
  llvm::DenseMap<DirectoryEntryRef, ClangRulesetsDirectoryState> Dirs;

private:
  std::unique_ptr<ClangRulesetsTiming> Timing;
  std::vector<ClangRulesetsEffectiveConfig *> CreatedEffectiveConfigs;
  llvm::StringMap<config::ClangRulesRule *> RuleByNamespacedName;

public:
  ClangRulesetsState(clang::CompilerInstance &InCI)
      : CI(InCI), Dirs(), Timing(std::make_unique<ClangRulesetsTiming>()),
        CreatedEffectiveConfigs(), RuleByNamespacedName(){};
  ClangRulesetsState(const ClangRulesetsState &) = delete;
  ClangRulesetsState(ClangRulesetsState &&) = delete;
  ~ClangRulesetsState() {
    for (const auto &Config : this->CreatedEffectiveConfigs) {
      delete Config;
    }
  }

  ClangRulesetsTiming *getTiming() { return this->Timing.get(); }

  std::unique_ptr<config::ClangRules>
  loadClangRulesFromPreprocessor(clang::FileID &FileID,
                                 clang::SourceManager &SrcMgr) {
    // Load the .clang-rules file.
    SourceMgrAdapter SMAdapter(
        SrcMgr, SrcMgr.getDiagnostics(), diag::err_clangrules_message,
        diag::warn_clangrules_message, diag::note_clangrules_message,
        SrcMgr.getFileEntryRefForID(FileID));
    std::unique_ptr<config::ClangRules> LoadedRules =
        std::make_unique<config::ClangRules>();
    llvm::yaml::Input YamlParse(SrcMgr.getBufferData(FileID), nullptr,
                                SMAdapter.getDiagHandler(),
                                SMAdapter.getDiagContext());
    YamlParse >> *LoadedRules;
    if (YamlParse.error()) {
      return nullptr;
    }

    // Track whether the loaded rules are still valid.
    bool StillValid = true;

    // Go through rules, make sure they aren't already prefixed, and then update
    // our in-memory version of the rules file to prefix them with the
    // namespace.
    for (auto &Rule : LoadedRules->Rules) {
      if (Rule.Name.find('/') != std::string::npos) {
        SrcMgr.getDiagnostics().Report(
            SrcMgr.getLocForStartOfFile(FileID),
            diag::err_clangrules_rule_name_is_prefixed)
            << Rule.Name;
        StillValid = false;
        continue;
      }
      std::string NamespacedName = LoadedRules->Namespace;
      NamespacedName.append("/");
      NamespacedName.append(Rule.Name);
      Rule.Name = NamespacedName;

      // Make sure this namespaced rule name isn't already taken.
      if (this->RuleByNamespacedName[Rule.Name] != nullptr) {
        SrcMgr.getDiagnostics().Report(SrcMgr.getLocForStartOfFile(FileID),
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
      }
    }

    // Go through rulesets and namespace both their name and any unprefixed
    // rules they enable, and normalize the severity on rules using the
    // default severity if it's not set.
    for (auto &Ruleset : LoadedRules->Rulesets) {
      if (Ruleset.Name.find('/') != std::string::npos) {
        SrcMgr.getDiagnostics().Report(
            SrcMgr.getLocForStartOfFile(FileID),
            diag::err_clangrules_ruleset_name_is_prefixed)
            << Ruleset.Name;
        StillValid = false;
      } else {
        std::string NamespacedName = LoadedRules->Namespace;
        NamespacedName.append("/");
        NamespacedName.append(Ruleset.Name);
        Ruleset.Name = NamespacedName;
      }
      if (Ruleset.Severity ==
          clang::rulesets::config::ClangRulesSeverity::CRS_NotSet) {
        SrcMgr.getDiagnostics().Report(
            SrcMgr.getLocForStartOfFile(FileID),
            diag::err_clangrules_ruleset_severity_is_notset)
            << Ruleset.Name;
        StillValid = false;
      }
      for (auto &Rule : Ruleset.Rules) {
        if (Rule.Name.find('/') == std::string::npos) {
          std::string NamespacedName = LoadedRules->Namespace;
          NamespacedName.append("/");
          NamespacedName.append(Rule.Name);
          Rule.Name = NamespacedName;
        }
        if (Rule.Severity ==
            clang::rulesets::config::ClangRulesSeverity::CRS_NotSet) {
          Rule.Severity = Ruleset.Severity;
        }
      }
    }

    // If we have a fatal error in loading the rules, release the memory
    // and treat the directory as if it has no rules at all.
    if (!StillValid) {
      return nullptr;
    }

    // Map all of the namespaced rule names to their locations in memory (as
    // part of LoadedRules).
    for (auto &Rule : LoadedRules->Rules) {
      this->RuleByNamespacedName[Rule.Name] = &Rule;
    }

    // Return the loaded rules.
    return LoadedRules;
  }

private:
  void materializeDirectoryState(ClangRulesetsDirectoryState &DirState,
                                 ASTContext &AST) {
    assert(!DirState.Materialized);

    // If we have an actual on-disk configuration, we need to merge that
    // with our parent.
    if (DirState.ActualOnDiskConfig &&
        DirState.ActualOnDiskConfig->Rulesets.size() > 0) {
      // Create our new effective configuration.
      auto *EffectiveConfig = new ClangRulesetsEffectiveConfig();

      // Get the materialized effective config of the parent, if we're not
      // a root directory, and then copy from that.
      if (DirState.ParentDirectory) {
        auto &ParentState = this->Dirs[*DirState.ParentDirectory];
        if (!ParentState.Materialized) {
          RULESET_TRACE("materializing: " << DirState.ParentDirectory->getName()
                                          << "\n");
          assert(&ParentState != &DirState);
          this->materializeDirectoryState(ParentState, AST);
          RULESET_TRACE("materializing done: "
                        << DirState.ParentDirectory->getName() << "\n");
        }
        if (ParentState.EffectiveConfig != nullptr) {
          // Copy the effective rules (which are namespaced rule names plus the
          // effective severity).
          EffectiveConfig->EffectiveRules =
              ParentState.EffectiveConfig->EffectiveRules;
        }
      }

      // For all of the rulesets in our rules, add them or update their existing
      // severity in the effective rules.
      bool StillValid = true;
      for (const auto &Ruleset : DirState.ActualOnDiskConfig->Rulesets) {
        for (const auto &RulesetRule : Ruleset.Rules) {
          // Lookup the rule by namespaced name. If this doesn't exist, then the
          // ruleset is referencing a rule that isn't known.
          auto *Rule = this->RuleByNamespacedName[RulesetRule.Name];
          if (Rule == nullptr) {
            AST.getDiagnostics().Report(diag::err_clangrules_rule_missing)
                << Ruleset.Name << RulesetRule.Name;
            StillValid = false;
          } else {
            EffectiveConfig->EffectiveRules[RulesetRule.Name] =
                ClangRulesetsEffectiveRule{Rule, RulesetRule.Severity};
          }
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
           It != EffectiveConfig->EffectiveRules.end(); ++It) {
        if (It->second.Severity == config::ClangRulesSeverity::CRS_Silence) {
          EffectiveConfig->EffectiveRules.erase(It);
        }
      }

      // Remove any effective rules that are Windows-only if we're not targeting
      // Windows. This allows us to exclude rules that check things like
      // __dllexport.
      if (!CI.getTarget().getTriple().isOSWindows()) {
        for (auto It = EffectiveConfig->EffectiveRules.begin();
             It != EffectiveConfig->EffectiveRules.end(); ++It) {
          if (It->second.Rule->WindowsOnly) {
            EffectiveConfig->EffectiveRules.erase(It);
          }
        }
      }

      // If there are no effective rules remaining, materialize this directory
      // as if there was no .clang-rules anywhere in the hierarchy.
      if (EffectiveConfig->EffectiveRules.size() == 0) {
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
          RULESET_TRACE("materializing: " << DirState.ParentDirectory->getName()
                                          << "\n");
          assert(&ParentState != &DirState);
          this->materializeDirectoryState(ParentState, AST);
          RULESET_TRACE("materializing done: "
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
#if RULESET_ENABLE_THREADING
      llvm::sys::SmartMutex<true> &Mutex;
#endif
      ASTContext &AST;
      const ClangRulesetsEffectiveRule &EffectiveRule;

    public:
      InstantiatedMatcherCallback(
#if RULESET_ENABLE_THREADING
          llvm::sys::SmartMutex<true> &InMutex,
#endif
          ASTContext &InAST, const ClangRulesetsEffectiveRule &InEffectiveRule)
          :
#if RULESET_ENABLE_THREADING
            Mutex(InMutex),
#endif
            AST(InAST), EffectiveRule(InEffectiveRule){};

      virtual void run(const clang::ast_matchers::MatchFinder::MatchResult
                           &Result) override {
        RULESET_TRACE("run() called for match result\n");

#if RULESET_ENABLE_THREADING
        // Obtain lock.
        this->Mutex.lock();
#endif

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
              clang::DiagnosticIDs::Level::Remark;
          switch (this->EffectiveRule.Severity) {
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

#if RULESET_ENABLE_THREADING
        // Release lock.
        this->Mutex.unlock();
#endif
      }
    };

    std::unique_ptr<ast_matchers::MatchFinder> Finder;
    llvm::DenseMap<const ClangRulesetsEffectiveRule *,
                   clang::ast_matchers::MatchFinder::MatchCallback *>
        Callbacks;
#if RULESET_ENABLE_THREADING
    llvm::sys::SmartMutex<true> &Mutex;
#endif
    ASTContext &AST;

  public:
    InstantiatedMatcher(
#if RULESET_ENABLE_THREADING
        llvm::sys::SmartMutex<true> &InMutex,
#endif
        ASTContext &InAST)
        : Finder(std::make_unique<ast_matchers::MatchFinder>()), Callbacks(),
#if RULESET_ENABLE_THREADING
          Mutex(InMutex),
#endif
          AST(InAST) {
    }
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
        auto *Callback = new InstantiatedMatcherCallback(
#if RULESET_ENABLE_THREADING
            this->Mutex,
#endif
            this->AST, EffectiveRule);
        RULESET_TRACE("adding dynamic matcher to finder\n");
        this->Finder->addDynamicMatcher(*Rule->MatcherParsed, Callback);
        this->Callbacks[&EffectiveRule] = Callback;
      }
    }

    void match(clang::Decl *Decl) {
      RULESET_TRACE("match called for decl\n");
      this->Finder->matchDecl(Decl, this->AST);
    }
  };

public:
  void runAnalysisOnTranslationUnit(ASTContext &AST) {
    RULESET_TIME_REGION(this->CI, Timer, this->Timing, RulesetAnalysisTimer);

    const auto *UnitDeclEntry = AST.getTranslationUnitDecl();
    if (UnitDeclEntry == nullptr) {
      RULESET_TRACE(
          "skipping AST analysis because there's no translation unit\n");
      return;
    }
    const SourceManager &SrcMgr = AST.getSourceManager();

    RULESET_TRACE("starting AST analysis\n");

    // Track the current file ID and current effective config, so that as we go
    // over decls in the same source file, we don't need to redo lookups.
    FileID CurrentFileID;
    ClangRulesetsEffectiveConfig *CurrentEffectiveConfig = nullptr;

    // Cached callbacks.
    std::map<ClangRulesetsEffectiveConfig *, InstantiatedMatcher *>
        SharedEffectiveConfigToInstantiatedMatchers;

#if RULESET_ENABLE_THREADING
    // Set up our mutex and thread pool.
    llvm::sys::SmartMutex<true> ThreadMutex;
    llvm::ThreadPool ThreadPool;
#endif

    // Iterate through all of the decls in the translation unit.
    for (const auto &DeclEntry : UnitDeclEntry->decls()) {
      bool FileChanged = false;
      {
        RULESET_TIME_REGION(this->CI, FileCheckTimer, this->Timing,
                            RulesetAnalysisFileCheckTimer);

        // Get the location of this decl.
        FileID NewFileID = SrcMgr.getFileID(DeclEntry->getLocation());
        if (NewFileID.isInvalid()) {
          // Ignore any decls that have no file ID.
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
        RULESET_TIME_REGION(this->CI, FileChangeTimer, this->Timing,
                            RulesetAnalysisFileChangeTimer);

        // Try to get the file entry for the file ID.
        auto FileEntry = SrcMgr.getFileEntryRefForID(CurrentFileID);
        if (!FileEntry) {
          // This is an unknown file - no rules apply.
          continue;
        }

        // Get the effective configuration that should now apply.
        auto DirState = this->Dirs.find(FileEntry->getDir());
        if (DirState == this->Dirs.end()) {
          // This is not a tracked directory - no rules apply.
          continue;
        }

        // Materialize this directory if needed.
        if (!DirState->second.Materialized) {
          RULESET_TIME_REGION(this->CI, MaterializationTimer, this->Timing,
                              RulesetAnalysisMaterializationTimer);
          this->materializeDirectoryState(DirState->second, AST);
        }

        // Set effective configuration.
        CurrentEffectiveConfig = DirState->second.EffectiveConfig;

        // If there is a config, instantiate the matcher we will use.
        if (CurrentEffectiveConfig != nullptr) {
          auto Matcher = new InstantiatedMatcher(
#if RULESET_ENABLE_THREADING
              ThreadMutex,
#endif
              const_cast<ASTContext &>(AST));
          for (const auto &EffectiveRule :
               CurrentEffectiveConfig->EffectiveRules) {
            RULESET_TRACE("adding rule to matcher: " << EffectiveRule.first
                                                     << "\n");
            Matcher->addRule(EffectiveRule.second);
          }
          RULESET_TRACE("instantiated matcher\n");
          SharedEffectiveConfigToInstantiatedMatchers[CurrentEffectiveConfig] =
              Matcher;
        }
      }

      // Only run matchers if this declaration has an effective config
      // associated with it.
      if (CurrentEffectiveConfig != nullptr) {
#if RULESET_ENABLE_THREADING
        RULESET_TIME_REGION(this->CI, ScheduleTimer, this->Timing,
                            RulesetAnalysisScheduleTimer);
#else
        RULESET_TIME_REGION(this->CI, ExecuteTimer, this->Timing,
                            RulesetAnalysisExecuteTimer);
#endif

        // Evaluate all of the matchers against this node.
        RULESET_TRACE("executing matcher\n");
        InstantiatedMatcher *Matcher =
            SharedEffectiveConfigToInstantiatedMatchers[CurrentEffectiveConfig];
#if RULESET_ENABLE_THREADING
        ThreadPool.async(
            [](Decl *DeclEntry, InstantiatedMatcher *Matcher) {
#endif
              Matcher->match(DeclEntry);
#if RULESET_ENABLE_THREADING
            },
            DeclEntry, Matcher);
#endif
      }
    }

#if RULESET_ENABLE_THREADING
    // Wait for matchers to run in threads.
    {
      RULESET_TIME_REGION(this->CI, WaitTimer, this->Timing,
                          RulesetAnalysisWaitTimer);
      ThreadPool.wait();
    }
#endif

    // Free all the matchers.
    for (const auto &KV : SharedEffectiveConfigToInstantiatedMatchers) {
      delete KV.second;
    }
    SharedEffectiveConfigToInstantiatedMatchers.clear();

    RULESET_TRACE("ending AST analysis\n");
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
    auto &SrcMgr = CI.getSourceManager();
    auto OptionalFileEntryRef = SrcMgr.getFileEntryRefForID(FID);
    if (!OptionalFileEntryRef.has_value()) {
      // If there's no file entry for the new file, we don't process it.
      return;
    }

    auto ContainingDirectory = OptionalFileEntryRef->getDir();
    if (!State->Dirs.contains(ContainingDirectory)) {
      RULESET_TIME_REGION(this->CI, Timer, this->State->getTiming(),
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
        auto ClangRulesFile =
            CI.getFileManager().getFileRef(ClangRulesPath, true, true);
        if (ClangRulesFile) {
          // We got a .clangrules file in this directory; load it into the
          // Clang source manager so we can report diagnostics etc.
          clang::FileID ClangRulesFileID =
              CI.getSourceManager().getOrCreateFileID(
                  ClangRulesFile.get(), SrcMgr::CharacteristicKind::C_User);
          State->Dirs[ContainingDirectory].ActualOnDiskConfig =
              State->loadClangRulesFromPreprocessor(ClangRulesFileID, SrcMgr);

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
          State->Dirs[ContainingDirectory].ActualOnDiskConfig = nullptr;
        }
        // Modify CurrentAbsolutePath so that it contains the next parent path
        // to evaluate.
        RULESET_TRACE("directory: " << CurrentAbsolutePath);
        CurrentAbsolutePath = llvm::sys::path::parent_path(CurrentAbsolutePath);
        RULESET_TRACE(" -> " << CurrentAbsolutePath << "\n");
        if (CurrentAbsolutePath.empty() ||
            (llvm::sys::path::is_style_windows(
                 llvm::sys::path::Style::native) &&
             CurrentAbsolutePath.ends_with(":"))) {
          // No further parent directories.
          break;
        } else {
          auto OptionalParentDirectory =
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
};

class ClangRulesetsConsumer : public ASTConsumer {
private:
  std::shared_ptr<ClangRulesetsState> State;

public:
  ClangRulesetsConsumer(std::shared_ptr<ClangRulesetsState> InState)
      : State(InState){};
  virtual ~ClangRulesetsConsumer() override = default;

  void HandleTranslationUnit(ASTContext &AST) override {
    RULESET_TRACE("Receiving translation unit for analysis\n");
    this->State->runAnalysisOnTranslationUnit(AST);
  }
};

std::unique_ptr<ASTConsumer>
ClangRulesetsProvider::CreateASTConsumer(clang::CompilerInstance &CI) {
  // Create our state that will be shared across consumers and the
  // preprocessor.
  RULESET_TRACE("Creating Clang rulesets state\n");
  std::shared_ptr<ClangRulesetsState> State =
      std::make_shared<ClangRulesetsState>(CI);

  // Register our preprocessor callbacks, which are used to discover rulesets
  // as files are included.
  CI.getPreprocessor().addPPCallbacks(
      std::make_unique<ClangRulesetsPPCallbacks>(State, CI));

  // Create and return our consumer for performing analysis.
  return std::make_unique<ClangRulesetsConsumer>(State);
}

} // namespace clang::rulesets