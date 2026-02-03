param()

foreach ($LlvmDir in (Get-ChildItem -Path $PSScriptRoot\llvm)) {
    if ($LlvmDir.Name -eq "21.x") {
        # not using 21.x with patch lists yet, since Unreal Engine doesn't target 21.x yet.
        continue
    }

    Push-Location $LlvmDir
    try {

        $Version = $LlvmDir.Name

        Write-Host "Reapplying patches to LLVM $Version ..."

        git am --abort

        git fetch --no-tags https://github.com/llvm/llvm-project/ release/${Version}:refs/temp
        git tag | % { git tag -d $_ }

        git -c advice.detachedHead=false checkout -f refs/temp
        git branch -f redpoint/${Version} refs/temp
        git checkout redpoint/${Version}

        $PatchList = @()
        foreach ($Patch in (Get-ChildItem -Path $PSScriptRoot\patches -Filter *.patch)) {
            $PatchList += $Patch
        }
        if (Test-Path $PSScriptRoot\patches\$Version) {
            foreach ($Patch in (Get-ChildItem -Path $PSScriptRoot\patches\$Version -Filter *.patch)) {
                $PatchList += $Patch
            }
        }
        $PatchList = ($PatchList | Sort-Object -Property Name)

        foreach ($Patch in $PatchList) {
            Write-Host "Applying $($Patch.Name) ..."
            Get-Content -Raw -Path $Patch.FullName | git am
            if ($LastExitCode -ne 0) {
                if ($Patch.Name -eq "000.core.build-system-changes.patch") {
                    # This patch is just deleting a bunch of junk.
                    Remove-Item -Force -Recurse .ci
                    Remove-Item -Force -Recurse .github
                    Remove-Item -Force README.md
                    git add .ci .github README.md
                    if ($LastExitCode -ne 0) { exit 1 }
                    git am --continue
                    if ($LastExitCode -ne 0) { exit 1 }
                } else {
                    Write-Error "Failed to apply patch $($Patch.Name) !"
                    exit 1
                }
            }
        }
        
    } finally {
        Pop-Location
    }
}