# Clang for Unreal Engine

This fork of LLVM/Clang that supports "custom static analysis during compilation" with .clang-rules files. Custom static analysis rules can also match against Unreal Engine UCLASS/etc. metadata associated with AST nodes. 

Please refer to the [GitHub Wiki](https://github.com/RedpointGames/llvm-project/wiki) for Getting Started and download instructions.

Each modified version of Clang is present as a submodule on this branch, to allow for patches on multiple versions to be maintained at the same time.