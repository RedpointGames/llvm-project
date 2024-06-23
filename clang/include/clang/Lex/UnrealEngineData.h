// Copyright June Rhodes. Apache License v2.0 with LLVM Exceptions.

// @unreal: BEGIN
#ifndef LLVM_CLANG_UNREAL_ENGINE_DATA_H
#define LLVM_CLANG_UNREAL_ENGINE_DATA_H

#include <string>

namespace clang {

enum UnrealType {
  UT_None = 0,
  UT_UClass,
  UT_UStruct,
  UT_UInterface,
  UT_UFunction,
  UT_UProperty,

  // Assigned to the IInterface associated classes of UInterface, since Unreal interfaces
  // have two CXXRecordDecls that make them up.
  UT_IInterface
};

struct UnrealSpecifier {
  /// The specifier name. This is always converted to lowercase, since Unreal
  /// specifiers are case insensitive.
  std::string SpecifierName;

  /// If the specifier has a value (after an = sign), this contains the value of
  /// the specifier. Eliminates any quotes around the value as well. If the
  /// specifier does not have a value, this will be an empty string.
  std::string SpecifierValue;
};

}; // namespace clang

#endif
// @unreal: END