<#
    Pester tests for First-On-Scene (Windows).
    Run:  Invoke-Pester .\tests\fos.Tests.ps1
#>
BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:Win       = Join-Path $Root 'scripts\win'
    $script:Fixtures  = Join-Path $Root 'tests\fixtures'
    Import-Module (Join-Path $Win 'FOS.Common.psm1') -Force

    function Invoke-FosTriageFixture {
        param([string]$Fixture)
        $cd = Join-Path $env:TEMP ("fostest_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $cd -Force | Out-Null
        Copy-Item (Join-Path $Fixtures $Fixture) (Join-Path $cd 'bundle.json')
        & (Join-Path $Win 'Invoke-Triage.ps1') -BundlePath (Join-Path $cd 'bundle.json') -CaseDir $cd | Out-Null
        $exit = $LASTEXITCODE
        $findings = Get-Content (Join-Path $cd 'findings.json') -Raw | ConvertFrom-Json
        [pscustomobject]@{ Exit = $exit; Findings = $findings; CaseDir = $cd }
    }
}

Describe 'Common library' {
    It 'computes the known SHA-256 of "abc"' {
        Get-FosStringSha256 'abc' | Should -Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    }
    It 'generates a structured case id' {
        New-FosCaseId 'HOST1' | Should -Match '^FOS-\d{8}-\d{6}-HOST1-[a-f0-9]{6}$'
    }
}

Describe 'Analyzer verdicts' {
    It 'returns ALL_CLEAR / exit 0 on a clean bundle' {
        $r = Invoke-FosTriageFixture 'clean_bundle.json'
        $r.Exit | Should -Be 0
        $r.Findings.verdict | Should -Be 'ALL_CLEAR'
        @($r.Findings.findings).Count | Should -Be 0
        Remove-Item $r.CaseDir -Recurse -Force
    }
    It 'returns PROBLEM_DETECTED / Breach / exit 21 on an infected bundle' {
        $r = Invoke-FosTriageFixture 'infected_bundle.json'
        $r.Exit | Should -Be 21
        $r.Findings.verdict | Should -Be 'PROBLEM_DETECTED'
        $r.Findings.classification | Should -Be 'Breach'
        $r.Findings.reasonCode | Should -Be 'RANSOMWARE_ENCRYPTED_FILES'
        Remove-Item $r.CaseDir -Recurse -Force
    }
    It 'maps known infected indicators to the expected rules' {
        $r = Invoke-FosTriageFixture 'infected_bundle.json'
        $ids = $r.Findings.findings.ruleId
        $ids | Should -Contain 'FOS-AV-001'
        $ids | Should -Contain 'FOS-NET-001'
        $ids | Should -Contain 'FOS-PSH-001'
        $ids | Should -Contain 'FOS-RAN-001'
        Remove-Item $r.CaseDir -Recurse -Force
    }
    It 'flags data-theft signals as PROBLEM_DETECTED on an exfiltration bundle' {
        $r = Invoke-FosTriageFixture 'exfil_bundle.json'
        $r.Exit | Should -Be 20
        $r.Findings.verdict | Should -Be 'PROBLEM_DETECTED'
        $r.Findings.classification | Should -Be 'Incident'
        $r.Findings.reasonCode | Should -Be 'SUSPICIOUS_DOWNLOAD_SOURCE'
        Remove-Item $r.CaseDir -Recurse -Force
    }
    It 'fires every exfiltration/collection rule on the exfil bundle' {
        $r = Invoke-FosTriageFixture 'exfil_bundle.json'
        $ids = $r.Findings.findings.ruleId
        foreach ($id in 'FOS-EXF-001','FOS-EXF-002','FOS-COL-001','FOS-EXF-003','FOS-EXF-004','FOS-EXF-005') {
            $ids | Should -Contain $id
        }
        Remove-Item $r.CaseDir -Recurse -Force
    }
}

Describe 'Evidence integrity' {
    It 'detects chain-of-custody tampering' {
        $cd = Join-Path $env:TEMP ("fostc_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $cd -Force | Out-Null
        Add-FosCocEntry -CaseDir $cd -Action 'A' -Detail 'one' | Out-Null
        Add-FosCocEntry -CaseDir $cd -Action 'B' -Detail 'two' | Out-Null
        (Test-FosCoc -CaseDir $cd).Valid | Should -BeTrue
        $coc = Join-Path $cd 'chain_of_custody.log'
        (Get-Content $coc) -replace 'one','HACKED' | Set-Content $coc -Encoding UTF8
        (Test-FosCoc -CaseDir $cd).Valid | Should -BeFalse
        Remove-Item $cd -Recurse -Force
    }
    It 'detects manifest tampering' {
        $cd = Join-Path $env:TEMP ("fosmn_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $cd -Force | Out-Null
        'evidence' | Out-File (Join-Path $cd 'bundle.json') -Encoding utf8
        New-FosManifest -CaseDir $cd -CaseId (New-FosCaseId) | Out-Null
        (Test-FosManifest -CaseDir $cd).Valid | Should -BeTrue
        'tampered' | Out-File (Join-Path $cd 'bundle.json') -Encoding utf8
        (Test-FosManifest -CaseDir $cd).Valid | Should -BeFalse
        Remove-Item $cd -Recurse -Force
    }
}
