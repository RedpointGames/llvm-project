unsigned getCustomDiagID(Level L, StringRef FormatString, StringRef Name);
bool getExistingCustomDiagIDs(StringRef Name,
                             SmallVectorImpl<diag::kind> &Diags);
std::optional<unsigned> getExistingCustomDiagID(StringRef Name,
                                                               Level L);