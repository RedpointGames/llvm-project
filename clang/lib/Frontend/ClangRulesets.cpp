#include "ClangRulesets.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/Dynamic/Parser.h"
#include "clang/Basic/SourceMgrAdapter.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/Support/RWMutex.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"

using namespace clang;

#if 0
#define RULESET_TRACE(x) llvm::errs() << x;
#else
#define RULESET_TRACE(x)
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

class ClangRulesetsState {
public:
  llvm::DenseMap<DirectoryEntryRef, ClangRulesetsDirectoryState> Dirs;

private:
  std::vector<ClangRulesetsEffectiveConfig *> CreatedEffectiveConfigs;
  llvm::StringMap<config::ClangRulesRule *> RuleByNamespacedName;
  llvm::ThreadPool ThreadPool;
  llvm::sys::SmartRWMutex<true> ThreadRWMutex;

  struct MissingClangRule {
    std::string NamespacedRulesetName;
    std::string NamespacedRuleName;
  };
  std::vector<MissingClangRule> MissingClangRules;

  struct DiagnosticToReport {
    const ClangRulesetsEffectiveRule *EffectiveRule;
    clang::SourceLocation CallsiteLoc;
    std::vector<std::pair<clang::SourceLocation, llvm::StringRef>> HintLocs;
  };
  std::map<ASTContext *, std::vector<DiagnosticToReport>> DiagnosticsToReport;

public:
  ClangRulesetsState()
      : Dirs(), CreatedEffectiveConfigs(), RuleByNamespacedName(),
        ThreadPool(){};
  ClangRulesetsState(const ClangRulesetsState &) = delete;
  ClangRulesetsState(ClangRulesetsState &&) = delete;
  ~ClangRulesetsState() {
    for (const auto &Config : this->CreatedEffectiveConfigs) {
      delete Config;
    }
  }

  std::unique_ptr<config::ClangRules>
  loadClangRules_fromPreprocessor(clang::FileID &FileID,
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
  void materializeDirectoryState_withinWriteLock(
      ClangRulesetsDirectoryState &DirState) {
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
          this->materializeDirectoryState_withinWriteLock(ParentState);
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
            MissingClangRules.push_back(
                MissingClangRule{Ruleset.Name, RulesetRule.Name});
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
          this->materializeDirectoryState_withinWriteLock(ParentState);
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

  class LockableClangRulesetsState {
  private:
    ClangRulesetsState *State;

  public:
    LockableClangRulesetsState(ClangRulesetsState *InState) : State(InState){};
    LockableClangRulesetsState(const LockableClangRulesetsState &) = delete;
    LockableClangRulesetsState(LockableClangRulesetsState &&) = delete;
    ~LockableClangRulesetsState() = default;

    ClangRulesetsEffectiveConfig *
    getEffectiveConfigForDirectoryEntry(const clang::DirectoryEntryRef &Dir) {
      // Obtain a read lock.
      RULESET_TRACE("getEffectiveConfigForDirectoryEntry: obtain read lock\n");
      this->State->ThreadRWMutex.lock_shared();
      auto DirState = State->Dirs.find(Dir);
      if (DirState == State->Dirs.end()) {
        // Release the read lock and return; this is not a tracked directory.
        RULESET_TRACE(
            "getEffectiveConfigForDirectoryEntry: release read lock\n");
        this->State->ThreadRWMutex.unlock_shared();
        return nullptr;
      }

      // If we haven't materialized this directory, upgrade to a
      // write lock and then materialize.
      if (!DirState->second.Materialized) {
        // Upgrade to write lock.
        RULESET_TRACE(
            "getEffectiveConfigForDirectoryEntry: release read lock\n");
        this->State->ThreadRWMutex.unlock_shared();
        RULESET_TRACE(
            "getEffectiveConfigForDirectoryEntry: obtain write lock\n");
        this->State->ThreadRWMutex.lock();

        // Check that another writer that was waiting didn't just
        // materialize this directory state.
        if (!DirState->second.Materialized) {
          RULESET_TRACE("materializing inside lock: "
                        << DirState->first.getName() << "\n");
          State->materializeDirectoryState_withinWriteLock(DirState->second);
          RULESET_TRACE("materializing inside lock done: "
                        << DirState->first.getName() << "\n");
        }

        // Read the effective config pointer while still in the write lock.
        auto *EffectiveConfig = DirState->second.EffectiveConfig;

        // Now release the write lock and return.
        RULESET_TRACE(
            "getEffectiveConfigForDirectoryEntry: release write lock\n");
        this->State->ThreadRWMutex.unlock();
        return EffectiveConfig;
      } else {
        // Read the effective config pointer while still in the read lock.
        auto *EffectiveConfig = DirState->second.EffectiveConfig;

        // Now release the read lock and return.
        RULESET_TRACE(
            "getEffectiveConfigForDirectoryEntry: release read lock\n");
        this->State->ThreadRWMutex.unlock_shared();
        return EffectiveConfig;
      }
    }

    void reportDiagnostic(ASTContext &AST,
                          const DiagnosticToReport &InDiagnosticToReport) {
      this->State->ThreadRWMutex.lock();
      this->State->DiagnosticsToReport[&AST].push_back(InDiagnosticToReport);
      this->State->ThreadRWMutex.unlock();
    }
  };

public:
  void receiveTranslationUnitForAnalysis(ASTContext &AST) {
    // @note: Capturing AST by reference is safe here because it's the same AST
    // that will be passed into the "wait consumer" when that runs after the
    // main consumer is done with the AST. Since the "wait consumer" blocks on
    // background threads, there's no way for the reference of AST to be
    // released while it's being used on the background thread.
    this->ThreadPool.async([this, &AST]() {
      LockableClangRulesetsState Lockable(this);
      RULESET_TRACE("background thread start\n");
      this->runTranslationUnitAnalysisOnBackgroundThread(Lockable, AST);
      RULESET_TRACE("background thread end\n");
    });
  }

private:
  class InstantiatedMatcher {
  private:
    class InstantiatedMatcherCallback
        : public clang::ast_matchers::MatchFinder::MatchCallback {
    private:
      LockableClangRulesetsState &State;
      ASTContext &AST;
      const ClangRulesetsEffectiveRule &EffectiveRule;

    public:
      InstantiatedMatcherCallback(
          LockableClangRulesetsState &InState, ASTContext &InAST,
          const ClangRulesetsEffectiveRule &InEffectiveRule)
          : State(InState), AST(InAST), EffectiveRule(InEffectiveRule){};

      virtual void run(const clang::ast_matchers::MatchFinder::MatchResult
                           &Result) override {
        RULESET_TRACE("run() called for match result\n");
        DiagnosticToReport Diagnostic = {};
        Diagnostic.EffectiveRule = &this->EffectiveRule;
        {
          auto CallsiteIt =
              Result.Nodes.getMap().find(this->EffectiveRule.Rule->Callsite);
          if (CallsiteIt == Result.Nodes.getMap().end()) {
            Diagnostic.CallsiteLoc =
                this->AST.getTranslationUnitDecl()->getBeginLoc();
          } else {
            Diagnostic.CallsiteLoc =
                CallsiteIt->second.getSourceRange().getBegin();
          }
        }
        for (const auto &HintKV : this->EffectiveRule.Rule->Hints) {
          auto HintIt = Result.Nodes.getMap().find(HintKV.first);
          if (HintIt != Result.Nodes.getMap().end()) {
            Diagnostic.HintLocs.push_back(
                std::pair<clang::SourceLocation, llvm::StringRef>(
                    HintIt->second.getSourceRange().getBegin(),
                    llvm::StringRef(HintKV.second)));
          }
        }
        this->State.reportDiagnostic(this->AST, Diagnostic);
      }
    };

    std::unique_ptr<ast_matchers::MatchFinder> Finder;
    llvm::DenseMap<const ClangRulesetsEffectiveRule *,
                   clang::ast_matchers::MatchFinder::MatchCallback *>
        Callbacks;
    LockableClangRulesetsState &State;
    ASTContext &AST;

  public:
    InstantiatedMatcher(LockableClangRulesetsState &InState, ASTContext &InAST)
        : Finder(std::make_unique<ast_matchers::MatchFinder>()), Callbacks(),
          State(InState), AST(InAST) {}
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
        auto *Callback = new InstantiatedMatcherCallback(this->State, this->AST,
                                                         EffectiveRule);
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

  static void runTranslationUnitAnalysisOnBackgroundThread(
      LockableClangRulesetsState &State, const ASTContext &AST) {
    const auto *UnitDeclEntry = AST.getTranslationUnitDecl();
    if (UnitDeclEntry == nullptr) {
      RULESET_TRACE(
          "skipping AST analysis because there's no translation unit\n");
      return;
    }
    const SourceManager &SrcMgr = AST.getSourceManager();

    RULESET_TRACE("starting AST analysis\n");

    // Track the last file ID and last directory entry, so that as we go
    // over decls in the same source file, we don't need to redo lookups.
    FileID LastFileID;
    ClangRulesetsEffectiveConfig *LastEffectiveConfig = nullptr;

    // Cached callbacks.
    std::map<ClangRulesetsEffectiveConfig *, InstantiatedMatcher *>
        SharedEffectiveConfigToInstantiatedMatchers;

    // Iterate through all of the decls in the translation unit.
    for (const auto &DeclEntry : UnitDeclEntry->decls()) {
      // Get the location of this decl.
      FileID NewFileID = SrcMgr.getFileID(DeclEntry->getLocation());
      if (NewFileID.isInvalid()) {
        // Ignore any decls that have no file ID.
        continue;
      }

      // If we're not in the same file as we were previously...
      if (NewFileID != LastFileID) {
        // @note: We always update LastFileID, even if the calls below are
        // unable to get valid info. This allows us to skip over decls quickly
        // if we know the last file ID won't actually resolve anywhere.
        LastFileID = NewFileID;
        LastEffectiveConfig = nullptr;

        // Try to get the file entry for the file ID.
        auto FileEntry = SrcMgr.getFileEntryRefForID(NewFileID);
        if (!FileEntry) {
          continue;
        }

        // Get the new effective config via the lockable state.
        LastEffectiveConfig =
            State.getEffectiveConfigForDirectoryEntry(FileEntry->getDir());

        // If there is a config, instantiate the matcher we will use.
        if (LastEffectiveConfig != nullptr) {
          auto Matcher =
              new InstantiatedMatcher(State, const_cast<ASTContext &>(AST));
          for (const auto &EffectiveRule :
               LastEffectiveConfig->EffectiveRules) {
            RULESET_TRACE("adding rule to matcher: " << EffectiveRule.first
                                                     << "\n");
            Matcher->addRule(EffectiveRule.second);
          }
          RULESET_TRACE("instantiated matcher\n");
          SharedEffectiveConfigToInstantiatedMatchers[LastEffectiveConfig] =
              Matcher;
        }
      }

      // If we have no .clang-rules effective config for this decl, skip.
      if (LastEffectiveConfig == nullptr) {
        continue;
      }

      // Evaluate all of the matchers against this node.
      RULESET_TRACE("executing matcher\n");
      SharedEffectiveConfigToInstantiatedMatchers[LastEffectiveConfig]->match(
          DeclEntry);
    }

    // Free all the matchers.
    for (const auto &KV : SharedEffectiveConfigToInstantiatedMatchers) {
      delete KV.second;
    }
    SharedEffectiveConfigToInstantiatedMatchers.clear();

    RULESET_TRACE("ending AST analysis\n");
  }

public:
  void blockUntilAnalysisOnBackgroundThreadsIsCompleteAndFlushDiagnostics(
      ASTContext &ReceivedAST) {
    // Wait for all current analysis to finish.
    this->ThreadPool.wait();

    // @note: We don't need to obtain a write lock here because only the main
    // thread calls receiveTranslationUnitForAnalysis to add new tasks to the
    // thread pool, and this function only runs on the main thread.

    // Flush all pending "missing rule" diagnostics.
    for (const auto &PendingError : this->MissingClangRules) {
      ReceivedAST.getDiagnostics().Report(diag::err_clangrules_rule_missing)
          << PendingError.NamespacedRulesetName
          << PendingError.NamespacedRuleName;
    }
    this->MissingClangRules.clear();

    // Flush diagnostics for this AST in particular.
    for (const auto &Diagnostic : this->DiagnosticsToReport[&ReceivedAST]) {
      // Report the error message.
      {
        clang::DiagnosticIDs::Level DiagnosticLevel =
            clang::DiagnosticIDs::Level::Remark;
        switch (Diagnostic.EffectiveRule->Severity) {
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
            ReceivedAST.getDiagnostics().getDiagnosticIDs()->getCustomDiagID(
                DiagnosticLevel, Diagnostic.EffectiveRule->Rule->ErrorMessage);
        ReceivedAST.getDiagnostics().Report(Diagnostic.CallsiteLoc,
                                            CallsiteDiagID);
      }

      // Report any attached hints.
      for (const auto &HintKV : Diagnostic.HintLocs) {
        auto HintDiagID =
            ReceivedAST.getDiagnostics().getDiagnosticIDs()->getCustomDiagID(
                clang::DiagnosticIDs::Note, HintKV.second);
        ReceivedAST.getDiagnostics().Report(HintKV.first, HintDiagID);
      }
    }
    this->DiagnosticsToReport.erase(&ReceivedAST);
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
      // This leaf directory hasn't been seen before. We need to make an
      // absolute path with '.' entries removed so that we can start traversing
      // up the directory tree.
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
              State->loadClangRules_fromPreprocessor(ClangRulesFileID, SrcMgr);
        } else {
          // We did not get a .clangrules file in this directory; cache that it
          // is empty.
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

class ClangRulesetsStartConsumer : public ASTConsumer {
private:
  std::shared_ptr<ClangRulesetsState> State;

public:
  ClangRulesetsStartConsumer(std::shared_ptr<ClangRulesetsState> InState)
      : State(InState){};
  virtual ~ClangRulesetsStartConsumer() override = default;

  void HandleTranslationUnit(ASTContext &AST) override {
    RULESET_TRACE("Receiving translation unit for analysis\n");
    this->State->receiveTranslationUnitForAnalysis(AST);
  }
};

class ClangRulesetsWaitConsumer : public ASTConsumer {
private:
  std::shared_ptr<ClangRulesetsState> State;

public:
  ClangRulesetsWaitConsumer(std::shared_ptr<ClangRulesetsState> InState)
      : State(InState){};
  virtual ~ClangRulesetsWaitConsumer() override = default;

  void HandleTranslationUnit(ASTContext &AST) override {
    RULESET_TRACE("Blocking until translation unit analysis complete\n");
    this->State
        ->blockUntilAnalysisOnBackgroundThreadsIsCompleteAndFlushDiagnostics(
            AST);
  }
};

void ClangRulesetsProvider::CreateAndAddASTConsumers(
    clang::CompilerInstance &CI,
    std::vector<std::unique_ptr<ASTConsumer>> &BeforeConsumers,
    std::vector<std::unique_ptr<ASTConsumer>> &AfterConsumers) {
  // Create our state that will be shared across consumers and the preprocessor.
  RULESET_TRACE("Creating Clang rulesets state\n");
  std::shared_ptr<ClangRulesetsState> State =
      std::make_shared<ClangRulesetsState>();

  // Register our preprocessor callbacks, which are used to discover rulesets as
  // files are included.
  CI.getPreprocessor().addPPCallbacks(
      std::make_unique<ClangRulesetsPPCallbacks>(State, CI));

  // Create our "start consumer" and "wait consumer". Because analysis can take
  // a long time, we run the analysis on a background thread while CodeGen is
  // happening, and then re-join the thread later with a "wait consumer".
  RULESET_TRACE("Attaching AST consumers\n");
  BeforeConsumers.push_back(
      std::make_unique<ClangRulesetsStartConsumer>(State));
  AfterConsumers.push_back(std::make_unique<ClangRulesetsWaitConsumer>(State));
}

} // namespace clang::rulesets