class CustomDiagDesc {
  LLVM_PREFERRED_TYPE(diag::Severity)
  unsigned DefaultSeverity : 3;
  LLVM_PREFERRED_TYPE(Class)
  unsigned DiagClass : 3;
  LLVM_PREFERRED_TYPE(bool)
  unsigned ShowInSystemHeader : 1;
  LLVM_PREFERRED_TYPE(bool)
  unsigned ShowInSystemMacro : 1;
  LLVM_PREFERRED_TYPE(bool)
  unsigned HasGroup : 1;
  diag::Group Group;
  std::string Description;
  std::string Name;

  auto get_as_tuple() const {
    return std::tuple(DefaultSeverity, DiagClass, ShowInSystemHeader,
                      ShowInSystemMacro, HasGroup, Group,
                      std::string_view{Description}, std::string_view{Name});
  }

public:
  CustomDiagDesc(diag::Severity DefaultSeverity, std::string Description,
                  unsigned Class = CLASS_WARNING,
                  bool ShowInSystemHeader = false,
                  bool ShowInSystemMacro = false,
                  std::optional<diag::Group> Group = std::nullopt,
                  std::string Name = "")
      : DefaultSeverity(static_cast<unsigned>(DefaultSeverity)),
        DiagClass(Class), ShowInSystemHeader(ShowInSystemHeader),
        ShowInSystemMacro(ShowInSystemMacro), HasGroup(Group != std::nullopt),
        Group(Group.value_or(diag::Group{})),
        Description(std::move(Description)),
        Name(std::move(Name)) {}

  std::optional<diag::Group> GetGroup() const {
    if (HasGroup)
      return Group;
    return std::nullopt;
  }

  diag::Severity GetDefaultSeverity() const {
    return static_cast<diag::Severity>(DefaultSeverity);
  }

  Class GetClass() const { return static_cast<Class>(DiagClass); }
  std::string_view GetName() const { return Name; }
  std::string_view GetDescription() const { return Description; }
  bool ShouldShowInSystemHeader() const { return ShowInSystemHeader; }

  friend bool operator==(const CustomDiagDesc &lhs,
                          const CustomDiagDesc &rhs) {
    return lhs.get_as_tuple() == rhs.get_as_tuple();
  }

  friend bool operator<(const CustomDiagDesc &lhs,
                        const CustomDiagDesc &rhs) {
    return lhs.get_as_tuple() < rhs.get_as_tuple();
  }
};

unsigned getRedpointDiagID(diag::Severity L, StringRef FormatString, StringRef Name);
bool getExistingRedpointDiagIDs(StringRef Name,
                             SmallVectorImpl<diag::kind> &Diags);
std::optional<unsigned> getExistingRedpointDiagID(StringRef Name,
                                                               diag::Severity L);