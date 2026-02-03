param([switch] $Generate, [switch] $Install, [switch] $InstallOnly, [switch] $Debug, [string] $Version = "19.x", [string] $VisualStudio = "C:\Program Files\Microsoft Visual Studio\2022\Community")

$global:ErrorActionPreference = 'Stop'

if (!(Test-Path "C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe")) {
    Write-Error "LLVM not found at C:\ProgramData\LLVM-Chainbuild; please download the official Clang/LLVM 19.x build and extract it to this path, such that C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe exists."
}

function Invoke-CmdScript {
  param(
    [String] $scriptName
  )
  $cmdLine = """$scriptName"" $args & set"
  & $Env:SystemRoot\system32\cmd.exe /c $cmdLine |
  select-string '^([^=]*)=(.*)$' | foreach-object {
    $varName = $_.Matches[0].Groups[1].Value
    $varValue = $_.Matches[0].Groups[2].Value
    set-item Env:$varName $varValue
  }
}

$RootPath = "$PSScriptRoot\.."
$CachePath = "$RootPath\cache"
$TempPath = "$RootPath\temp"

if (!(Test-Path $CachePath)) {
    New-Item -ItemType Directory $CachePath
}
$env:FASTBUILD_CACHE_PATH = $CachePath

if (!(Test-Path $TempPath)) {
    New-Item -ItemType Directory $TempPath
}
Push-Location $TempPath
try {
    # Set the build path.
    $BuildPathDebug = "$RootPath\llvm\$Version\build\win64\debug"
    $BuildPathRelease = "$RootPath\llvm\$Version\build\win64\release"
    $CMakeCommand = (Get-Command cmake).Source
    $CMakeCommandArguments = @()
    $CMakeCommandGenerateArguments = @(
        "-G",
        "FASTBuild"
    )

    Write-Host "BuildPathDebug: $BuildPathDebug"
    Write-Host "BuildPathRelease: $BuildPathRelease"
    Write-Host "CMakeCommand: $CMakeCommand"
    Write-Host "CMakeCommandArguments: $CMakeCommandArguments"
    Write-Host "CMakeCommandGenerateArguments: $CMakeCommandGenerateArguments"

    # Create the session ID for this build.
    $env:CMAKE_UBA_SESSION_ID = "$(Get-Random)"

    # Initialize MSVC environment.
    Invoke-CmdScript "$VisualStudio\VC\Auxiliary\Build\vcvarsall.bat" x64

    # Generate compile_command.json
    $env:CMAKE_EXPORT_COMPILE_COMMANDS="true"

    # Generate CMake projects if needed.
    if ($Generate `
        -or (!(Test-Path "$BuildPathDebug\CMakeCache.txt")) `
        -or (!(Test-Path "$BuildPathRelease\CMakeCache.txt"))) {
        if (!(Test-Path $BuildPathDebug)) {
            New-Item -ItemType Directory $BuildPathDebug | Out-Null
        }
        if (!(Test-Path $BuildPathRelease)) {
            New-Item -ItemType Directory $BuildPathRelease | Out-Null
        }
        & $CMakeCommand $CMakeCommandArguments $CMakeCommandGenerateArguments `
            "-DCMAKE_MAKE_PROGRAM=C:\Users\juner\Downloads\FASTBuild-Windows-x64-v1.18\FBuild.exe" `
            "-DLLVM_ENABLE_PROJECTS:STRING=clang;lld" `
            "-DCMAKE_C_COMPILER=C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe" `
            "-DCMAKE_CXX_COMPILER=C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe" `
            "-DCMAKE_ASM_COMPILER=C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe" `
            "-DCMAKE_RC_COMPILER=C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64/rc.exe" `
            "-DCMAKE_MT=C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64/mt.exe" `
            -DLLVM_INSTALL_TOOLCHAIN_ONLY:BOOL=TRUE `
            -DLLVM_INCLUDE_BENCHMARKS:BOOL=FALSE `
            -DLLVM_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_INCLUDE_EXAMPLES:BOOL=FALSE `
            -DLLVM_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_ENABLE_DIA_SDK:BOOL=FALSE `
            -DCMAKE_BUILD_TYPE=Debug `
            -DCMAKE_CFG_INTDIR=Debug `
            "-DCMAKE_INSTALL_PREFIX=C:\Program Files\LLVM" `
            $LauncherFlags `
            "-H$RootPath\llvm\$Version\llvm" `
            "-B$BuildPathDebug"
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
        & $CMakeCommand $CMakeCommandArguments $CMakeCommandGenerateArguments `
            "-DCMAKE_MAKE_PROGRAM=C:\Users\juner\Downloads\FASTBuild-Windows-x64-v1.18\FBuild.exe" `
            "-DLLVM_ENABLE_PROJECTS:STRING=clang;lld" `
            "-DCMAKE_C_COMPILER=C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe" `
            "-DCMAKE_CXX_COMPILER=C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe" `
            "-DCMAKE_ASM_COMPILER=C:\ProgramData\LLVM-Chainbuild\bin\clang-cl.exe" `
            "-DCMAKE_RC_COMPILER=C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64/rc.exe" `
            "-DCMAKE_MT=C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64/mt.exe" `
            -DLLVM_INSTALL_TOOLCHAIN_ONLY:BOOL=TRUE `
            -DLLVM_INCLUDE_BENCHMARKS:BOOL=FALSE `
            -DLLVM_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_INCLUDE_EXAMPLES:BOOL=FALSE `
            -DLLVM_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_TESTS:BOOL=FALSE `
            -DCLANG_INCLUDE_DOCS:BOOL=FALSE `
            -DLLVM_ENABLE_DIA_SDK:BOOL=FALSE `
            -DCMAKE_BUILD_TYPE=Release `
            -DCMAKE_CFG_INTDIR=Release `
            "-DCMAKE_INSTALL_PREFIX=C:\Program Files\LLVM" `
            $LauncherFlags `
            "-H$RootPath\llvm\$Version\llvm" `
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
        & $CMakeCommand $CMakeCommandArguments `
            --build $BuildPath `
            --config $BuildConfiguration `
            -- `
            -cache `
            -dist
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }

    # Install if requested.
    if ($Install -or $InstallOnly) {
        & $CMakeCommand `
            --install $BuildPath `
            --config $BuildConfiguration
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }
} finally {
    Pop-Location
}