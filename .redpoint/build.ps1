param([switch] $Generate, [switch] $Install, [switch] $InstallOnly, [switch] $Debug)

$global:ErrorActionPreference = 'Stop'

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

$UbaViaUet = (Test-Path "C:\ProgramData\UET\Current\uet.exe")

Push-Location "$PSScriptRoot\.."
try {
    # Set the build path.
    $BuildPathDebug = "build\win64\debug"
    $BuildPathRelease = "build\win64\release"
    $LauncherFlags = @()
    $UbaCores = @()
    if ($UbaViaUet) {
        $LauncherFlags += "-DCMAKE_C_COMPILER_LAUNCHER=$PSScriptRoot\uet-cmake.bat"
        $LauncherFlags += "-DCMAKE_CXX_COMPILER_LAUNCHER=$PSScriptRoot\uet-cmake.bat"
        $UbaCores += "-j256"
    }

    # Create the session ID for this build.
    $env:CMAKE_UBA_SESSION_ID = "$(Get-Random)"

    # Initialize MSVC environment.
    Invoke-CmdScript "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

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
            #-T host=x64 -A x64 `
        & 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
            -G "Ninja" `
            "-DCMAKE_MAKE_PROGRAM=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" `
            "-DLLVM_ENABLE_PROJECTS:STRING=clang;lld" `
            "-DCMAKE_C_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe" `
            "-DCMAKE_CXX_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe" `
            "-DCMAKE_ASM_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe" `
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
            -Hllvm `
            "-B$BuildPathDebug"
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
        & 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
            -G "Ninja" `
            "-DCMAKE_MAKE_PROGRAM=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" `
            "-DLLVM_ENABLE_PROJECTS:STRING=clang;lld" `
            "-DCMAKE_C_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe" `
            "-DCMAKE_CXX_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe" `
            "-DCMAKE_ASM_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe" `
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
        # Start UBA worker if needed.
        if ($UbaViaUet) {
            Start-Process -NoNewWindow -FilePath "C:\Work\uet\UET\uet\bin\Debug\net8.0\win-x64\uet.exe" -ArgumentList @("internal", "cmake-uba-server")
        }

        & 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
            --build $BuildPath `
            --config $BuildConfiguration `
            $UbaCores
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }

    # Install if requested.
    if ($Install -or $InstallOnly) {
        & 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' `
            --install $BuildPath `
            --config $BuildConfiguration
        if ($LastExitCode -ne 0) {
            exit $LastExitCode
        }
    }
} finally {
    Pop-Location
}