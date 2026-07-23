#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Module principal ADHardeningAudit - Orchestrateur de l'audit AD.

.DESCRIPTION
    Charge tous les sous-modules de detection, remediation et reporting.
    Expose la fonction Invoke-ADHardeningAudit comme point d'entree principal.

.NOTES
    Auteur  : ADHardeningAudit
    Version : 1.0.0
    Domaine : mogador.local
#>

Set-StrictMode -Version Latest

#region --- Chargement des sous-modules ---

$SubFolders = @('Detect', 'Remediate', 'Report')

foreach ($folder in $SubFolders) {
    $folderPath = Join-Path $PSScriptRoot $folder
    if (Test-Path $folderPath) {
        Get-ChildItem -Path $folderPath -Filter '*.ps1' -Recurse | ForEach-Object {
            try {
                . $_.FullName
                Write-Verbose "[MODULE] Chargement : $($_.Name)"
            }
            catch {
                Write-Warning "[MODULE] Erreur lors du chargement de $($_.Name) : $_"
            }
        }
    }
}

#endregion

#region --- Fonction d'orchestration principale ---

function Invoke-ADHardeningAudit {
    <#
    .SYNOPSIS
        Lance l'audit complet Active Directory et genere le rapport.

    .DESCRIPTION
        Orchestre les 4 modules de detection, agregge les findings sous forme
        de PSCustomObjects, calcule les scores de risque et appelle New-AuditReport.

    .PARAMETER Domain
        FQDN du domaine a auditer. Par defaut : domaine courant.

    .PARAMETER OutputPath
        Dossier de sortie pour les rapports HTML et CSV. Par defaut : .\AuditResults

    .PARAMETER SkipRemediation
        Si specifie, ne pas executer les modules de remediation (mode audit pur).

    .PARAMETER WhatIf
        Passe le flag -WhatIf a toutes les fonctions de remediation.

    .EXAMPLE
        Invoke-ADHardeningAudit -Domain mogador.local -OutputPath C:\Audit\Results

    .EXAMPLE
        Invoke-ADHardeningAudit -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$PSScriptRoot\AuditResults",

        [Parameter(Mandatory = $false)]
        [switch]$SkipRemediation
    )

    $startTime = Get-Date
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "`n" -NoNewline
    Write-Host "===================================================================╗" -ForegroundColor Cyan
    Write-Host "|          ADHardeningAudit v1.0 - Audit Active Directory          |" -ForegroundColor Cyan
    Write-Host "|                    Domaine : $Domain$((' ' * [Math]::Max(0, 34 - $Domain.Length)))|" -ForegroundColor Cyan
    Write-Host "|                    Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')                   |" -ForegroundColor Cyan
    Write-Host "===================================================================╝" -ForegroundColor Cyan
    Write-Host ""

    #region Detection

    Write-Host "[1/4] " -ForegroundColor Yellow -NoNewline
    Write-Host "Detection des delegations dangereuses..." -ForegroundColor White
    try {
        $delegationFindings = Find-DangerousDelegation -Domain $Domain -ErrorAction Stop
        $allFindings.AddRange([PSCustomObject[]]$delegationFindings)
        Write-Host "      → $($delegationFindings.Count) finding(s) detecte(s)" -ForegroundColor $(if ($delegationFindings.Count -gt 0) { 'Red' } else { 'Green' })
    }
    catch {
        Write-Warning "      Erreur module Delegation : $_"
    }

    Write-Host "[2/4] " -ForegroundColor Yellow -NoNewline
    Write-Host "Detection des problemes d'hygiene des comptes..." -ForegroundColor White
    try {
        $hygieneFindings = Find-AccountHygieneIssues -Domain $Domain -ErrorAction Stop
        $allFindings.AddRange([PSCustomObject[]]$hygieneFindings)
        Write-Host "      → $($hygieneFindings.Count) finding(s) detecte(s)" -ForegroundColor $(if ($hygieneFindings.Count -gt 0) { 'Red' } else { 'Green' })
    }
    catch {
        Write-Warning "      Erreur module AccountHygiene : $_"
    }

    Write-Host "[3/4] " -ForegroundColor Yellow -NoNewline
    Write-Host "Detection des chemins d'escalade de privileges..." -ForegroundColor White
    try {
        $escalationFindings = Find-PrivilegeEscalationPaths -Domain $Domain -ErrorAction Stop
        $allFindings.AddRange([PSCustomObject[]]$escalationFindings)
        Write-Host "      → $($escalationFindings.Count) finding(s) detecte(s)" -ForegroundColor $(if ($escalationFindings.Count -gt 0) { 'Red' } else { 'Green' })
    }
    catch {
        Write-Warning "      Erreur module EscalationPath : $_"
    }

    Write-Host "[4/4] " -ForegroundColor Yellow -NoNewline
    Write-Host "Analyse des ACL (mode explain-only)..." -ForegroundColor White
    try {
        $aclFindings = Find-ACLAbuses -Domain $Domain -ErrorAction Stop
        $allFindings.AddRange([PSCustomObject[]]$aclFindings)
        Write-Host "      → $($aclFindings.Count) finding(s) detecte(s)" -ForegroundColor $(if ($aclFindings.Count -gt 0) { 'Red' } else { 'Green' })
    }
    catch {
        Write-Warning "      Erreur module ACLAbuse : $_"
    }

    #endregion

    #region Resume console

    $critical = @($allFindings | Where-Object Severity -eq 'Critique').Count
    $high      = @($allFindings | Where-Object Severity -eq 'Eleve').Count
    $medium    = @($allFindings | Where-Object Severity -eq 'Moyen').Count
    $low       = @($allFindings | Where-Object Severity -eq 'Faible').Count

    Write-Host ""
    Write-Host "------------------------------------------┐" -ForegroundColor Cyan
    Write-Host "|            RESUME DE L'AUDIT             |" -ForegroundColor Cyan
    Write-Host "-------------------------------------------" -ForegroundColor Cyan
    Write-Host "|  Total findings  : $($allFindings.Count.ToString().PadRight(20))|" -ForegroundColor White
    Write-Host "|  [Critique] Critique     : $($critical.ToString().PadRight(20))|" -ForegroundColor Red
    Write-Host "|  [Eleve] Eleve        : $($high.ToString().PadRight(20))|" -ForegroundColor DarkYellow
    Write-Host "|  [Moyen] Moyen        : $($medium.ToString().PadRight(20))|" -ForegroundColor Yellow
    Write-Host "|  [Faible] Faible       : $($low.ToString().PadRight(20))|" -ForegroundColor Green
    Write-Host "------------------------------------------┘" -ForegroundColor Cyan
    Write-Host ""

    #endregion

    #region Generation du rapport

    Write-Host "[RAPPORT] Generation des rapports HTML et CSV..." -ForegroundColor Cyan
    $reportPaths = New-AuditReport -Findings $allFindings -Domain $Domain -OutputPath $OutputPath
    Write-Host "[RAPPORT] HTML : $($reportPaths.HTML)" -ForegroundColor Green
    Write-Host "[RAPPORT] CSV  : $($reportPaths.CSV)" -ForegroundColor Green

    #endregion

    $duration = (Get-Date) - $startTime
    Write-Host ""
    Write-Host "Audit termine en $([Math]::Round($duration.TotalSeconds, 1))s" -ForegroundColor Cyan

    # Retourner les findings pour usage en pipeline
    return $allFindings
}

#endregion
