namespace clang {
namespace diag {
class CustomDiagInfoEntry {
public:
  DiagnosticIDs::Level Level;
  std::string Name;
  std::string Description;
  unsigned DiagID;

  CustomDiagInfoEntry() {}
  CustomDiagInfoEntry(DiagnosticIDs::Level InLevel, std::string InName,
                      std::string InDescription, unsigned InDiagID)
      : Level(InLevel), Name(InName), Description(InDescription),
        DiagID(InDiagID) {}
};

class CustomDiagInfo {
  std::vector<CustomDiagInfoEntry> DiagInfo;
  llvm::StringMap<std::vector<CustomDiagInfoEntry>> DiagInfoByName;

public:
  /// getName - Return the name of the specified custom
  /// diagnostic.
  StringRef getName(unsigned DiagID) const {
    assert(DiagID - DIAG_UPPER_LIMIT < DiagInfo.size() &&
           "Invalid diagnostic ID");
    return DiagInfo[DiagID - DIAG_UPPER_LIMIT].Name;
  }

  /// getDescription - Return the description of the specified custom
  /// diagnostic.
  StringRef getDescription(unsigned DiagID) const {
    assert(DiagID - DIAG_UPPER_LIMIT < DiagInfo.size() &&
           "Invalid diagnostic ID");
    return DiagInfo[DiagID - DIAG_UPPER_LIMIT].Description;
  }

  /// getLevel - Return the level of the specified custom diagnostic.
  DiagnosticIDs::Level getLevel(unsigned DiagID) const {
    assert(DiagID - DIAG_UPPER_LIMIT < DiagInfo.size() &&
           "Invalid diagnostic ID");
    return DiagInfo[DiagID - DIAG_UPPER_LIMIT].Level;
  }

  std::optional<unsigned> tryGetDiagID(StringRef Name,
                                       DiagnosticIDs::Level L) const {
    auto It = this->DiagInfoByName.find(Name);
    if (It == this->DiagInfoByName.end()) {
      return std::optional<unsigned>();
    }
    for (const auto &E : It->getValue()) {
      if (E.Level == L) {
        return E.DiagID;
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
      Diags.push_back(E.DiagID);
    }
    return true;
  }

  unsigned getOrCreateDiagID(DiagnosticIDs::Level L, StringRef Message,
                             DiagnosticIDs &Diags, StringRef *Name = nullptr) {
    // Check to see if it already exists.
    StringRef NameResolved =
        Name == nullptr ? std::to_string(llvm::xxHash64(Message)) : *Name;
    auto It = this->DiagInfoByName.find(NameResolved);
    if (It != this->DiagInfoByName.end()) {
      for (const auto &E : It->getValue()) {
        if (E.Level == L) {
          return E.DiagID;
        }
      }
    }

    // If not, assign a new ID.
    unsigned ID = this->DiagInfo.size() + DIAG_UPPER_LIMIT;
    auto Entry = CustomDiagInfoEntry(L, NameResolved.str(), Message.str(), ID);
    this->DiagInfo.push_back(Entry);
    this->DiagInfoByName[NameResolved].push_back(Entry);
    return ID;
  }
};

} // namespace diag
} // namespace clang

unsigned DiagnosticIDs::getCustomDiagID(Level L, StringRef FormatString,
                                        StringRef Name) {
  if (!CustomDiagInfo)
    CustomDiagInfo.reset(new diag::CustomDiagInfo());
  return CustomDiagInfo->getOrCreateDiagID(L, FormatString, *this, &Name);
}

bool DiagnosticIDs::getExistingCustomDiagIDs(
    StringRef Name, SmallVectorImpl<diag::kind> &Diags) {
  if (!CustomDiagInfo) {
    CustomDiagInfo.reset(new diag::CustomDiagInfo());
  }
  return !CustomDiagInfo->tryGetDiagIDs(Name, Diags);
}

std::optional<unsigned> DiagnosticIDs::getExistingCustomDiagID(StringRef Name,
                                                                Level L) {
  if (!CustomDiagInfo) {
    CustomDiagInfo.reset(new diag::CustomDiagInfo());
  }
  return CustomDiagInfo->tryGetDiagID(Name, L);
}