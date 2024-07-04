param([switch] $Generate, [switch] $Install, [switch] $InstallOnly, [switch] $Debug)

$global:ErrorActionPreference = 'Stop'

Push-Location "$PSScriptRoot\.."
try {
    # Set the build path.
    $BuildPathDebug = "build\win64\debug"
    $BuildPathRelease = "build\win64\release"

    # Generate CMake projects if needed.
    if ($Generate `
        -or (!(Test-Path "$BuildPathDebug\LLVM.sln")) `
        -or (!(Test-Path "$BuildPathRelease\LLVM.sln"))) {
        if (!(Test-Path $BuildPathDebug)) {
            New-Item -ItemType Directory $BuildPathDebug | Out-Null
        }
        if (!(Test-Path $BuildPathRelease)) {
            New-Item -ItemType Directory $BuildPathRelease | Out-Null
        }
        & 'C:\Program Files\CMake\bin\cmake.exe' `
            -T host=x64 -A x64 `
            "-DLLVM_ENABLE_PROJECTS:STRING=clang;lld" `
            -DLLVM_INSTALL_TOOLCHAIN_ONLY:BOOL=TRUE `
            -DLLVM_INCLUDE_BENCHMARKS:BOOL=FALSE `
            -DLLVM_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_INCLUDE_EXAMPLES:BOOL=FALSE `
            -DLLVM_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_ENABLE_DIA_SDK:BOOL=FALSE `
            -DCMAKE_BUILD_TYPE=Debug `
            -DCMAKE_CONFIGURATION_TYPES=Debug `
            -Hllvm `
            "-B$BuildPathDebug"
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
        & 'C:\Program Files\CMake\bin\cmake.exe' `
            -T host=x64 -A x64 `
            "-DLLVM_ENABLE_PROJECTS:STRING=clang;lld" `
            -DLLVM_INSTALL_TOOLCHAIN_ONLY:BOOL=TRUE `
            -DLLVM_INCLUDE_BENCHMARKS:BOOL=FALSE `
            -DLLVM_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_INCLUDE_EXAMPLES:BOOL=FALSE `
            -DLLVM_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_ENABLE_DIA_SDK:BOOL=FALSE `
            -DCMAKE_BUILD_TYPE=Release `
            -DCMAKE_CONFIGURATION_TYPES=Release `
            -Hllvm `
            "-B$BuildPathRelease"
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }

    # Determine what build path we're going to use.
    $BuildPath = $BuildPathRelease
    $BuildConfiguration = "Release"
    if ($Debug) {
        $BuildPath = $BuildPathDebug
        $BuildConfiguration = "Debug"
    }

    # Build if not only installing.
    if (!$InstallOnly) {
        & 'C:\Program Files\CMake\bin\cmake.exe' `
            --build $BuildPath `
            --config $BuildConfiguration
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }

    # Install if requested.
    if ($Install -or $InstallOnly) {
        & 'C:\Program Files\CMake\bin\cmake.exe' `
            --install $BuildPath `
            --config $BuildConfiguration
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }
} finally {
    Pop-Location
}