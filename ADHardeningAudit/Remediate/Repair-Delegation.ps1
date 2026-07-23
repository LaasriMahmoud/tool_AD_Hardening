function Repair-DangerousDelegation {
    <#
    .SYNOPSIS
        Remediation des delegations Kerberos dangereuses.

    .DESCRIPTION
        Retire la delegation non contrainte (TrustedForDelegation) ou la Protocol Transition
        (TrustedToAuthForDelegation) sur les comptes identifies comme dangereux.

        UTILISATION OBLIGATOIRE avec -WhatIf en soutenance pour ne pas modifier la production.

    .PARAMETER ObjectName
        SamAccountName du compte a remedier.

    .PARAMETER ObjectType
        Type d'objet : 'User' ou 'Computer'

    .PARAMETER RemoveUnconstrained
        Si specifie, retire TrustedForDelegation (Unconstrained Delegation).

    .PARAMETER RemoveProtocolTransition
        Si specifie, retire TrustedToAuthForDelegation (Protocol Transition).

    .PARAMETER ClearDelegateTo
        Si specifie, vide msDS-AllowedToDelegateTo (liste des services cibles).

    .PARAMETER Domain
        FQDN du domaine AD cible.

    .PARAMETER WhatIf
        Affiche les actions qui seraient effectuees sans les executer.

    .PARAMETER Confirm
        Demande une confirmation avant chaque modification.

    .EXAMPLE
        # Demo soutenance - ne modifie rien
        Repair-DangerousDelegation -ObjectName 'svc-plurihotel' -ObjectType User `
                                   -RemoveUnconstrained -WhatIf

    .EXAMPLE
        # Remise en production - avec confirmation interactive
        Repair-DangerousDelegation -ObjectName 'WORKSTATION01' -ObjectType Computer `
                                   -RemoveUnconstrained -Confirm
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Computer')]
        [string]$ObjectType,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveUnconstrained,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveProtocolTransition,

        [Parameter(Mandatory = $false)]
        [switch]$ClearDelegateTo,

        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    # Recuperer l'objet AD
    try {
        if ($ObjectType -eq 'User') {
            $adObject = Get-ADUser -Identity $ObjectName `
                        -Properties TrustedForDelegation, TrustedToAuthForDelegation,
                                    'msDS-AllowedToDelegateTo', DistinguishedName `
                        -Server $Domain -ErrorAction Stop
        }
        else {
            $adObject = Get-ADComputer -Identity $ObjectName `
                        -Properties TrustedForDelegation, TrustedToAuthForDelegation,
                                    'msDS-AllowedToDelegateTo', DistinguishedName `
                        -Server $Domain -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Impossible de recuperer l objet [$ObjectName] de type [$ObjectType] : $_"
        return
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  REMEDIATION - Delegation - $ObjectName ($ObjectType)  " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DN : $($adObject.DistinguishedName)" -ForegroundColor Gray
    Write-Host "  TrustedForDelegation        : $($adObject.TrustedForDelegation)" -ForegroundColor $(if ($adObject.TrustedForDelegation) {'Red'} else {'Green'})
    Write-Host "  TrustedToAuthForDelegation  : $($adObject.TrustedToAuthForDelegation)" -ForegroundColor $(if ($adObject.TrustedToAuthForDelegation) {'Red'} else {'Green'})
    Write-Host "  msDS-AllowedToDelegateTo    : $($adObject.'msDS-AllowedToDelegateTo' -join ' | ')" -ForegroundColor Gray
    Write-Host ""

    $changesMade = 0

    #region Retrait Unconstrained Delegation

    if ($RemoveUnconstrained -and $adObject.TrustedForDelegation) {
        $action = "Retirer TrustedForDelegation sur $ObjectType [$ObjectName]"

        if ($PSCmdlet.ShouldProcess($ObjectName, $action)) {
            try {
                if ($ObjectType -eq 'User') {
                    Set-ADUser -Identity $ObjectName -TrustedForDelegation $false `
                               -Server $Domain -ErrorAction Stop
                }
                else {
                    Set-ADComputer -Identity $ObjectName -TrustedForDelegation $false `
                                   -Server $Domain -ErrorAction Stop
                }
                Write-Host "  [OK] TrustedForDelegation = False sur [$ObjectName]" -ForegroundColor Green
                $changesMade++
            }
            catch {
                Write-Error "  [ERREUR] Impossible de modifier TrustedForDelegation : $_"
            }
        }
    }
    elseif ($RemoveUnconstrained -and -not $adObject.TrustedForDelegation) {
        Write-Host "  [INFO] TrustedForDelegation est deja False sur [$ObjectName] - rien a faire." -ForegroundColor Yellow
    }

    #endregion

    #region Retrait Protocol Transition

    if ($RemoveProtocolTransition -and $adObject.TrustedToAuthForDelegation) {
        $action = "Retirer TrustedToAuthForDelegation (Protocol Transition) sur $ObjectType [$ObjectName]"

        if ($PSCmdlet.ShouldProcess($ObjectName, $action)) {
            try {
                if ($ObjectType -eq 'User') {
                    Set-ADAccountControl -Identity $ObjectName `
                                         -TrustedToAuthForDelegation $false `
                                         -Server $Domain -ErrorAction Stop
                }
                else {
                    Set-ADComputer -Identity $ObjectName `
                                   -TrustedToAuthForDelegation $false `
                                   -Server $Domain -ErrorAction Stop
                }
                Write-Host "  [OK] TrustedToAuthForDelegation = False sur [$ObjectName]" -ForegroundColor Green
                $changesMade++
            }
            catch {
                Write-Error "  [ERREUR] Impossible de retirer Protocol Transition : $_"
            }
        }
    }

    #endregion

    #region Vider la liste des services cibles

    if ($ClearDelegateTo -and $adObject.'msDS-AllowedToDelegateTo') {
        $currentServices = $adObject.'msDS-AllowedToDelegateTo' -join ', '
        $action = "Vider msDS-AllowedToDelegateTo sur [$ObjectName] (services actuels : $currentServices)"

        if ($PSCmdlet.ShouldProcess($ObjectName, $action)) {
            try {
                if ($ObjectType -eq 'User') {
                    Set-ADUser -Identity $ObjectName `
                               -Clear 'msDS-AllowedToDelegateTo' `
                               -Server $Domain -ErrorAction Stop
                }
                else {
                    Set-ADComputer -Identity $ObjectName `
                                   -Clear 'msDS-AllowedToDelegateTo' `
                                   -Server $Domain -ErrorAction Stop
                }
                Write-Host "  [OK] msDS-AllowedToDelegateTo vide sur [$ObjectName]" -ForegroundColor Green
                $changesMade++
            }
            catch {
                Write-Error "  [ERREUR] Impossible de vider msDS-AllowedToDelegateTo : $_"
            }
        }
    }

    #endregion

    Write-Host ""
    if ($WhatIfPreference) {
        Write-Host "  [WHATIF] Aucune modification effectuee - mode simulation." -ForegroundColor Yellow
        Write-Host "  Relancer sans -WhatIf pour appliquer les changements." -ForegroundColor Yellow
    }
    else {
        Write-Host "  $changesMade modification(s) appliquee(s) sur [$ObjectName]." -ForegroundColor Cyan
    }
    Write-Host ""
}
