function Repair-AccountHygieneIssues {
    <#
    .SYNOPSIS
        Remediation des problemes d'hygiene des comptes AD.

    .DESCRIPTION
        Trois types de corrections possibles :
        1. ASREP    : Remet DoesNotRequirePreAuth a False (corrige AS-REP Roasting)
        2. Stale    : Desactive les comptes inactifs depuis plus de N jours
        3. Reversible : Desactive le chiffrement reversible des mots de passe

        IMPORTANT : Ce module NE change PAS automatiquement les mots de passe des comptes
        de service Kerberoastable — c est trop risque de faire ca sans connaitre les systemes
        qui utilisent ce compte. Il signale seulement le probleme.

    .PARAMETER Type
        Type de correction : ASREP, Stale, ou Reversible

    .PARAMETER UserName
        SamAccountName du compte a corriger. Si absent avec -Type Stale, traite tous les stale.

    .PARAMETER StaleThresholdDays
        Seuil d inactivite pour -Type Stale. Default : 90 jours.

    .PARAMETER Domain
        FQDN du domaine.

    .PARAMETER WhatIf
        Simule sans executer.

    .PARAMETER Confirm
        Demande confirmation.

    .EXAMPLE
        # Demo soutenance
        Repair-AccountHygieneIssues -Type ASREP -UserName 'jdupont' -WhatIf

    .EXAMPLE
        Repair-AccountHygieneIssues -Type Stale -StaleThresholdDays 90 -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('ASREP', 'Stale', 'Reversible')]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [string]$UserName,

        [Parameter(Mandatory = $false)]
        [int]$StaleThresholdDays = 90,

        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  REMEDIATION - Account Hygiene - Type : $Type         " -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""

    switch ($Type) {

        #region ASREP : Reactiver la pre-authentification Kerberos

        'ASREP' {
            if ($UserName) {
                # Compte specifique
                $targets = @(Get-ADUser -Identity $UserName `
                              -Properties DoesNotRequirePreAuth, DistinguishedName `
                              -Server $Domain -ErrorAction Stop)
            }
            else {
                # Tous les comptes AS-REP Roastable
                $targets = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
                            -Properties DoesNotRequirePreAuth, DistinguishedName `
                            -Server $Domain -ErrorAction Stop
            }

            foreach ($user in $targets) {
                if (-not $user.DoesNotRequirePreAuth) {
                    Write-Host "  [SKIP] $($user.SamAccountName) : Pre-auth deja activee" -ForegroundColor Gray
                    continue
                }

                $action = "Reactiver la pre-authentification Kerberos sur [$($user.SamAccountName)] (corrige AS-REP Roasting)"
                Write-Host "  Cible : $($user.SamAccountName) ($($user.DistinguishedName))" -ForegroundColor White

                if ($PSCmdlet.ShouldProcess($user.SamAccountName, $action)) {
                    try {
                        Set-ADUser -Identity $user.SamAccountName `
                                   -DoesNotRequirePreAuth $false `
                                   -Server $Domain -ErrorAction Stop
                        Write-Host "  [OK] DoesNotRequirePreAuth = False sur [$($user.SamAccountName)]" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "  [ERREUR] $($user.SamAccountName) : $_"
                    }
                }
            }
        }

        #endregion

        #region Stale : Desactiver les comptes inactifs

        'Stale' {
            $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)

            if ($UserName) {
                $targets = @(Get-ADUser -Identity $UserName `
                              -Properties LastLogonDate, Enabled, DistinguishedName `
                              -Server $Domain -ErrorAction Stop)
            }
            else {
                $targets = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $staleDate } `
                            -Properties LastLogonDate, Enabled, DistinguishedName `
                            -Server $Domain -ErrorAction Stop
            }

            Write-Host "  Seuil d inactivite : $StaleThresholdDays jours (avant le $($staleDate.ToString('yyyy-MM-dd')))" -ForegroundColor Gray
            Write-Host "  Comptes cibles : $($targets.Count)" -ForegroundColor White
            Write-Host ""

            # Afficher l'impact avant toute action
            Write-Host "  PREVIEW DE L'IMPACT :" -ForegroundColor Yellow
            foreach ($user in $targets) {
                $daysSince = if ($user.LastLogonDate) {
                    [Math]::Round(((Get-Date) - $user.LastLogonDate).TotalDays)
                } else { 'N/A' }
                Write-Host "  → $($user.SamAccountName.PadRight(30)) | Inactif depuis : $daysSince j" -ForegroundColor $(if ([int]$daysSince -gt 365) {'Red'} else {'Yellow'})
            }
            Write-Host ""

            foreach ($user in $targets) {
                if (-not $user.Enabled) {
                    Write-Host "  [SKIP] $($user.SamAccountName) : deja desactive" -ForegroundColor Gray
                    continue
                }

                $daysSince = if ($user.LastLogonDate) {
                    [Math]::Round(((Get-Date) - $user.LastLogonDate).TotalDays)
                } else { 'Jamais connecte' }

                $action = "Desactiver le compte inactif [$($user.SamAccountName)] (inactif depuis $daysSince jours)"

                if ($PSCmdlet.ShouldProcess($user.SamAccountName, $action)) {
                    try {
                        Disable-ADAccount -Identity $user.SamAccountName `
                                          -Server $Domain -ErrorAction Stop
                        Write-Host "  [OK] Compte [$($user.SamAccountName)] desactive" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "  [ERREUR] $($user.SamAccountName) : $_"
                    }
                }
            }
        }

        #endregion

        #region Reversible : Desactiver le chiffrement reversible

        'Reversible' {
            if ($UserName) {
                $targets = @(Get-ADUser -Identity $UserName `
                              -Properties AllowReversiblePasswordEncryption, DistinguishedName `
                              -Server $Domain -ErrorAction Stop)
            }
            else {
                $targets = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true } `
                            -Properties AllowReversiblePasswordEncryption, DistinguishedName `
                            -Server $Domain -ErrorAction Stop
            }

            Write-Host "  ATTENTION : Apres correction, un changement de mot de passe est requis !" -ForegroundColor Red
            Write-Host ""

            foreach ($user in $targets) {
                if (-not $user.AllowReversiblePasswordEncryption) {
                    Write-Host "  [SKIP] $($user.SamAccountName) : chiffrement reversible deja desactive" -ForegroundColor Gray
                    continue
                }

                $action = "Desactiver AllowReversiblePasswordEncryption sur [$($user.SamAccountName)] (ATTENTION : necessite changement de mot de passe ensuite)"

                if ($PSCmdlet.ShouldProcess($user.SamAccountName, $action)) {
                    try {
                        Set-ADUser -Identity $user.SamAccountName `
                                   -AllowReversiblePasswordEncryption $false `
                                   -Server $Domain -ErrorAction Stop
                        Write-Host "  [OK] AllowReversiblePasswordEncryption = False sur [$($user.SamAccountName)]" -ForegroundColor Green
                        Write-Host "  [!] Forcer un changement de mdp : Set-ADAccountPassword '$($user.SamAccountName)' -Reset" -ForegroundColor Yellow
                    }
                    catch {
                        Write-Error "  [ERREUR] $($user.SamAccountName) : $_"
                    }
                }
            }
        }

        #endregion
    }

    Write-Host ""
    if ($WhatIfPreference) {
        Write-Host "  [WHATIF] Simulation terminee. Aucune modification effectuee." -ForegroundColor Yellow
        Write-Host "  Relancer sans -WhatIf pour appliquer les corrections." -ForegroundColor Yellow
    }
    Write-Host ""
}
