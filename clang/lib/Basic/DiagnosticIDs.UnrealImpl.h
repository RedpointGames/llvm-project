
namespace clang {
namespace diag {
using CustomDiagDesc = DiagnosticIDs::CustomDiagDesc;
class CustomDiagInfo {
  std::vector<CustomDiagDesc> DiagInfo;
  llvm::StringMap<std::vector<std::pair<CustomDiagDesc, unsigned>>> DiagInfoByName;
  std::map<CustomDiagDesc, unsigned> DiagIDs;
  std::map<diag::Group, std::vector<unsigned>> GroupToDiags;

public:
  /// getDescription - Return the description of the specified custom
  /// diagnostic.
  const CustomDiagDesc &getDescription(unsigned DiagID) const {
    assert(DiagID - DIAG_UPPER_LIMIT < DiagInfo.size() &&
           "Invalid diagnostic ID");
    return DiagInfo[DiagID - DIAG_UPPER_LIMIT];
  }

  unsigned getOrCreateDiagID(DiagnosticIDs::CustomDiagDesc D) {
    // Check to see if it already exists.
    std::map<CustomDiagDesc, unsigned>::iterator I = DiagIDs.lower_bound(D);
    if (I != DiagIDs.end() && I->first == D)
      return I->second;

    std::string GeneratedName = std::to_string(llvm::xxHash64(D.GetDescription()));

    // If not, assign a new ID.
    unsigned ID = DiagInfo.size() + DIAG_UPPER_LIMIT;
    DiagIDs.insert(std::make_pair(D, ID));
    DiagInfo.push_back(D);
    DiagInfoByName[GeneratedName].push_back(std::make_pair(D, ID));
    if (auto Group = D.GetGroup())
      GroupToDiags[*Group].emplace_back(ID);
    return ID;
  }

  unsigned getOrCreateRedpointDiagID(diag::Severity Severity, StringRef Message, StringRef Name) {
    // Check to see if it already exists.
    auto It = this->DiagInfoByName.find(Name);
    if (It != this->DiagInfoByName.end()) {
      for (const auto &E : It->getValue()) {
        if (E.first.GetDefaultSeverity() == Severity) {
          return E.second;
        }
      }
    }

    // If not, assign a new ID.
    unsigned ID = this->DiagInfo.size() + DIAG_UPPER_LIMIT;
    auto Entry = CustomDiagDesc(
      Severity, 
      Message.str(), 
      CLASS_WARNING, 
      false, 
      false, 
      std::nullopt, 
      Name.str());
    this->DiagIDs.insert(std::make_pair(Entry, ID));
    this->DiagInfo.push_back(Entry);
    this->DiagInfoByName[Name].push_back(std::make_pair(Entry, ID));
    return ID;
  }

  ArrayRef<unsigned> getDiagsInGroup(diag::Group G) const {
    if (auto Diags = GroupToDiags.find(G); Diags != GroupToDiags.end())
      return Diags->second;
    return {};
  }

  std::optional<unsigned> tryGetDiagID(StringRef Name,
                                       diag::Severity L) const {
    auto It = this->DiagInfoByName.find(Name);
    if (It == this->DiagInfoByName.end()) {
      return std::optional<unsigned>();
    }
    for (const auto &E : It->getValue()) {
      if (E.first.GetDefaultSeverity() == L) {
        return E.second;
      }
    }
    return std::optional<unsigned>();
  }

  bool tryGetDiagIDs(StringRef Name, SmallVectorImpl<diag::kind> &Diags) const {
    auto It = this->DiagInfoByName.find(Name);
    if (It == this->DiagInfoByName.end()) {
      return false;
    }
    for (const auto &E : It->getValue()) {
      Diags.push_back(E.second);
    }
    return true;
  }
};

} // namespace diag
} // namespace clang

unsigned DiagnosticIDs::getRedpointDiagID(
    diag::Severity L, 
    StringRef FormatString,
    StringRef Name) {
  if (!CustomDiagInfo)
    CustomDiagInfo.reset(new diag::CustomDiagInfo());
  return CustomDiagInfo->getOrCreateRedpointDiagID(L, FormatString, Name);
}

bool DiagnosticIDs::getExistingRedpointDiagIDs(
    StringRef Name, SmallVectorImpl<diag::kind> &Diags) {
  if (!CustomDiagInfo) {
    CustomDiagInfo.reset(new diag::CustomDiagInfo());
  }
  return !CustomDiagInfo->tryGetDiagIDs(Name, Diags);
}

std::optional<unsigned> DiagnosticIDs::getExistingRedpointDiagID(StringRef Name,
                                                                diag::Severity L) {
  if (!CustomDiagInfo) {
    CustomDiagInfo.reset(new diag::CustomDiagInfo());
  }
  return CustomDiagInfo->tryGetDiagID(Name, L);
}