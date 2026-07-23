<#
.SYNOPSIS
    Point d'entree unique de l'outil ADHardeningAudit.
    Lance l'audit complet du domaine Active Directory et genere le rapport.

.DESCRIPTION
    Ce script est le seul fichier a executer pour une demo complete.
    Il importe le module ADHardeningAudit et lance Invoke-ADHardeningAudit.

    Usage soutenance recommande :
        .\Run-FullAudit.ps1 -Domain mogador.local -WhatIf
        .\Run-FullAudit.ps1 -Domain mogador.local

    Pour la demo des remediations uniquement :
        .\Run-FullAudit.ps1 -Domain mogador.local -RemediateDemo

.PARAMETER Domain
    FQDN du domaine AD a auditer. Par defaut : domaine courant ($env:USERDNSDOMAIN)

.PARAMETER OutputPath
    Dossier de sortie pour les rapports HTML et CSV. Par defaut : .\AuditResults

.PARAMETER RemediateDemo
    Si specifie, lance une demo des 3 modules de remediation en mode -WhatIf
    apres l'audit (ne modifie rien).

.PARAMETER ReportOnly
    Ne lance que la generation du rapport depuis un CSV existant (non implemente dans v1).

.PARAMETER Verbose
    Mode verbeux - affiche le detail de chaque verification.

.EXAMPLE
    # Audit complet - soutenance
    .\Run-FullAudit.ps1 -Domain mogador.local

.EXAMPLE
    # Audit + demo remediation WhatIf
    .\Run-FullAudit.ps1 -Domain mogador.local -RemediateDemo

.EXAMPLE
    # Mode verbeux pour le debug
    .\Run-FullAudit.ps1 -Domain mogador.local -Verbose

.NOTES
    Prerequis :
    - PowerShell 5.1+
    - Module ActiveDirectory (RSAT) installe
    - Droits en lecture sur l'AD (Domain User suffit pour la detection)
    - Droits Domain Admin pour les remediations

    IMPORTANT SOUTENANCE :
    Ne jamais executer les remediations en live sans avoir teste en -WhatIf avant !
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false)]
    [string]$Domain = $env:USERDNSDOMAIN,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$PSScriptRoot\AuditResults",

    [Parameter(Mandatory = $false)]
    [switch]$RemediateDemo
)

# ─── Banniere d'accueil ────────────────────────────────────────────────────────

Clear-Host
Write-Host @"

  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                                                                       ║
  ║        █████╗ ██████╗     ██╗  ██╗ █████╗ ██████╗ ██████╗           ║
  ║       ██╔══██╗██╔══██╗    ██║  ██║██╔══██╗██╔══██╗██╔══██╗          ║
  ║       ███████║██║  ██║    ███████║███████║██████╔╝██║  ██║           ║
  ║       ██╔══██║██║  ██║    ██╔══██║██╔══██║██╔══██╗██║  ██║           ║
  ║       ██║  ██║██████╔╝    ██║  ██║██║  ██║██║  ██║██████╔╝           ║
  ║       ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝           ║
  ║                                                                       ║
  ║         HARDENING AUDIT TOOL v1.0 | mogador.local                    ║
  ║         Audit & Remediation Active Directory                          ║
  ║                                                                       ║
  ╚═══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "  Domaine cible  : " -NoNewline -ForegroundColor Gray
Write-Host $Domain -ForegroundColor Yellow
Write-Host "  Date           : " -NoNewline -ForegroundColor Gray
Write-Host (Get-Date -Format 'dd/MM/yyyy HH:mm:ss') -ForegroundColor White
Write-Host "  Utilisateur    : " -NoNewline -ForegroundColor Gray
Write-Host "$env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "  Sortie         : " -NoNewline -ForegroundColor Gray
Write-Host $OutputPath -ForegroundColor White
Write-Host ""

# ─── Verification des prerequis ───────────────────────────────────────────────

Write-Host "[ PRE-REQUIS ]" -ForegroundColor Cyan

# Verifier le module ActiveDirectory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "  [!] Module ActiveDirectory non disponible." -ForegroundColor Red
    Write-Host "      Installer RSAT : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Yellow
    Write-Host "      Ou depuis Parametres > Fonctionnalites facultatives > Outils RSAT" -ForegroundColor Yellow
    exit 1
}
Write-Host "  [OK] Module ActiveDirectory disponible" -ForegroundColor Green

# Verifier la connectivite au domaine
try {
    $null = Get-ADDomain -Server $Domain -ErrorAction Stop
    Write-Host "  [OK] Connectivite au domaine [$Domain] confirmee" -ForegroundColor Green
}
catch {
    Write-Host "  [!] Impossible de joindre le domaine [$Domain] : $_" -ForegroundColor Red
    Write-Host "      Verifier la connectivite reseau et les credentials." -ForegroundColor Yellow
    exit 1
}

# ─── Chargement du module ─────────────────────────────────────────────────────

Write-Host ""
Write-Host "[ MODULE ]" -ForegroundColor Cyan

$modulePath = Join-Path $PSScriptRoot 'ADHardeningAudit.psd1'

if (-not (Test-Path $modulePath)) {
    Write-Host "  [!] Module introuvable : $modulePath" -ForegroundColor Red
    Write-Host "      Assurez-vous que la structure ADHardeningAudit/ est bien presente." -ForegroundColor Yellow
    exit 1
}

try {
    # Forcer le rechargement si deja importe
    if (Get-Module ADHardeningAudit) {
        Remove-Module ADHardeningAudit -Force
    }
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-Host "  [OK] Module ADHardeningAudit v1.0 charge" -ForegroundColor Green
}
catch {
    Write-Host "  [!] Erreur lors du chargement du module : $_" -ForegroundColor Red
    exit 1
}

# ─── Lancement de l'audit ─────────────────────────────────────────────────────

Write-Host ""
Write-Host "[ AUDIT ]" -ForegroundColor Cyan
Write-Host ""

$allFindings = Invoke-ADHardeningAudit -Domain $Domain -OutputPath $OutputPath

# ─── Demo des remediations (WhatIf) ───────────────────────────────────────────

if ($RemediateDemo) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  DEMO REMEDIATION - MODE WHATIF (aucune modification reelle)  " -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""

    # Demo 1 : Delegation
    $delegFindings = $allFindings | Where-Object { $_.Category -eq 'Delegation' -and $_.CanRemediate }
    if ($delegFindings) {
        $first = $delegFindings | Select-Object -First 1
        Write-Host "[ DEMO 1/3 ] Reparation delegation sur : $($first.Object)" -ForegroundColor Yellow
        Repair-DangerousDelegation -ObjectName $first.Object `
                                    -ObjectType $first.ObjectType `
                                    -RemoveUnconstrained `
                                    -Domain $Domain `
                                    -WhatIf
    }
    else {
        Write-Host "[ DEMO 1/3 ] Aucun finding delegation remedier - skipping" -ForegroundColor Gray
    }

    # Demo 2 : Account Hygiene (ASREP)
    $asrepFindings = $allFindings | Where-Object { $_.FindingName -like '*AS-REP*' -and $_.CanRemediate }
    if ($asrepFindings) {
        $first = $asrepFindings | Select-Object -First 1
        Write-Host "[ DEMO 2/3 ] Correction AS-REP Roasting sur : $($first.Object)" -ForegroundColor Yellow
        Repair-AccountHygieneIssues -Type ASREP -UserName $first.Object -Domain $Domain -WhatIf
    }
    else {
        Write-Host "[ DEMO 2/3 ] Aucun compte AS-REP trouve - skipping" -ForegroundColor Gray
    }

    # Demo 3 : Escalation Path (nesting)
    $nestingFindings = $allFindings | Where-Object { $_.FindingName -like '*Nesting*' -and $_.CanRemediate }
    if ($nestingFindings) {
        $first = $nestingFindings | Select-Object -First 1
        Write-Host "[ DEMO 3/3 ] Retrait nesting : $($first.Object) de $($first.ParentGroup)" -ForegroundColor Yellow
        Repair-EscalationPaths -Type RemoveNesting `
                                -NestedGroupName $first.Object `
                                -ParentGroupName $first.ParentGroup `
                                -Domain $Domain `
                                -WhatIf
    }
    else {
        Write-Host "[ DEMO 3/3 ] Aucun nesting dangereux trouve - skipping" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  [FIN DEMO] Toutes les remediations ont ete simulees en -WhatIf." -ForegroundColor Magenta
    Write-Host "  Aucune modification n a ete apportee au domaine [$Domain]." -ForegroundColor Magenta
}

# ─── Recap final ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                     AUDIT TERMINE                             " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Le rapport HTML a ete ouvert dans votre navigateur." -ForegroundColor Green
Write-Host "  Les fichiers sont disponibles dans : $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "  Commandes utiles pour la soutenance :" -ForegroundColor Yellow
Write-Host "  ─────────────────────────────────────" -ForegroundColor Gray
Write-Host "  # Audit seul :" -ForegroundColor Gray
Write-Host "  .\Run-FullAudit.ps1 -Domain $Domain" -ForegroundColor White
Write-Host ""
Write-Host "  # Audit + demo remediation :" -ForegroundColor Gray
Write-Host "  .\Run-FullAudit.ps1 -Domain $Domain -RemediateDemo" -ForegroundColor White
Write-Host ""
Write-Host "  # Remediation specifique (WhatIf) :" -ForegroundColor Gray
Write-Host "  Repair-DangerousDelegation -ObjectName 'svc-plurihotel' -ObjectType User -RemoveUnconstrained -WhatIf" -ForegroundColor White
Write-Host "  Repair-EscalationPaths -Type RemoveNesting -NestedGroupName 'IT-Support' -ParentGroupName 'Domain Admins' -WhatIf" -ForegroundColor White
Write-Host ""
