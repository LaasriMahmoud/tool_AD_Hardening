function Repair-EscalationPaths {
    <#
    .SYNOPSIS
        Remediation des chemins d'escalade de privileges (nesting, AdminCount orphelins).

    .DESCRIPTION
        Deux types de corrections :
        1. RemoveNesting   : Retire un groupe imbrique d'un groupe Tier-0
        2. FixAdminCount   : Remet AdminCount a 0 sur les comptes orphelins

        Avant toute action, affiche l'impact complet (quels droits sont perdus).
        Concu pour etre utilise avec -WhatIf en demonstration.

    .PARAMETER Type
        Type de correction : RemoveNesting ou FixAdminCount

    .PARAMETER NestedGroupName
        Nom du groupe imbrique a retirer (requis pour RemoveNesting)

    .PARAMETER ParentGroupName
        Nom du groupe parent dont on retire le groupe imbrique (requis pour RemoveNesting)

    .PARAMETER UserName
        SamAccountName du compte a corriger (requis pour FixAdminCount specifique)

    .PARAMETER Domain
        FQDN du domaine.

    .PARAMETER WhatIf
        Simule sans executer.

    .PARAMETER Confirm
        Demande confirmation.

    .EXAMPLE
        # Demo soutenance - retire IT-Support de Domain Admins sans modifier
        Repair-EscalationPaths -Type RemoveNesting `
                               -NestedGroupName 'IT-Support' `
                               -ParentGroupName 'Domain Admins' `
                               -WhatIf

    .EXAMPLE
        Repair-EscalationPaths -Type FixAdminCount -UserName 'jdupont' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('RemoveNesting', 'FixAdminCount')]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [string]$NestedGroupName,

        [Parameter(Mandatory = $false)]
        [string]$ParentGroupName,

        [Parameter(Mandatory = $false)]
        [string]$UserName,

        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  REMEDIATION - Escalation Path - Type : $Type         " -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""

    switch ($Type) {

        #region RemoveNesting : Retrait d'un groupe imbrique

        'RemoveNesting' {
            if (-not $NestedGroupName -or -not $ParentGroupName) {
                Write-Error "Les parametres -NestedGroupName et -ParentGroupName sont obligatoires pour le type RemoveNesting."
                return
            }

            # Verifier que le nesting existe
            try {
                $parentGroup = Get-ADGroup -Identity $ParentGroupName `
                               -Properties Members -Server $Domain -ErrorAction Stop
                $nestedGroup = Get-ADGroup -Identity $NestedGroupName `
                               -Properties Members -Server $Domain -ErrorAction Stop
            }
            catch {
                Write-Error "Impossible de trouver les groupes [$NestedGroupName] ou [$ParentGroupName] : $_"
                return
            }

            $isNested = $parentGroup.Members | Where-Object { $_ -like "*$($nestedGroup.DistinguishedName)*" }
            if (-not $isNested) {
                Write-Host "  [INFO] [$NestedGroupName] n est pas membre direct de [$ParentGroupName]." -ForegroundColor Yellow
                Write-Host "         Verifiez le nesting avec : Get-ADGroupMember '$ParentGroupName' | Where-Object Name -eq '$NestedGroupName'" -ForegroundColor Gray
                return
            }

            # Afficher l'impact complet
            Write-Host "  ANALYSE D'IMPACT" -ForegroundColor Yellow
            Write-Host "  -----------------------------------------------------" -ForegroundColor Gray
            Write-Host "  Groupe a retirer  : $NestedGroupName" -ForegroundColor White
            Write-Host "  Groupe parent     : $ParentGroupName" -ForegroundColor White
            Write-Host ""

            # Membres du groupe imbrique qui perdront les droits du parent
            $nestedMembers = @()
            try {
                $nestedMembers = Get-ADGroupMember -Identity $NestedGroupName `
                                 -Recursive -Server $Domain -ErrorAction Stop
            }
            catch {}

            Write-Host "  Membres de [$NestedGroupName] qui perdront leurs droits [$ParentGroupName] :" -ForegroundColor Yellow
            foreach ($member in $nestedMembers) {
                Write-Host "    → $($member.Name) ($($member.objectClass))" -ForegroundColor White
            }
            Write-Host ""

            # Autres groupes dont $NestedGroupName est membre (pour contexte)
            $otherParents = @()
            try {
                $otherParents = Get-ADPrincipalGroupMembership -Identity $NestedGroupName `
                                -Server $Domain -ErrorAction SilentlyContinue |
                                Where-Object { $_.Name -ne $ParentGroupName }
            }
            catch {}

            if ($otherParents) {
                Write-Host "  Autres groupes parents de [$NestedGroupName] (non touches) :" -ForegroundColor Gray
                foreach ($og in $otherParents) {
                    Write-Host "    - $($og.Name)" -ForegroundColor Gray
                }
                Write-Host ""
            }

            # Effectuer la suppression
            $action = "Retirer [$NestedGroupName] du groupe [$ParentGroupName] - $($nestedMembers.Count) compte(s) perdront leurs droits [$ParentGroupName]"

            if ($PSCmdlet.ShouldProcess("$NestedGroupName → $ParentGroupName", $action)) {
                try {
                    Remove-ADGroupMember -Identity $ParentGroupName `
                                         -Members $NestedGroupName `
                                         -Server $Domain `
                                         -Confirm:$false `
                                         -ErrorAction Stop
                    Write-Host "  [OK] [$NestedGroupName] retire de [$ParentGroupName]" -ForegroundColor Green
                    Write-Host "  [!] $($nestedMembers.Count) compte(s) n ont plus les privileges de [$ParentGroupName]" -ForegroundColor Yellow
                }
                catch {
                    Write-Error "  [ERREUR] Impossible de retirer le groupe : $_"
                }
            }
        }

        #endregion

        #region FixAdminCount : Corriger AdminCount orphelins

        'FixAdminCount' {
            $targets = @()

            if ($UserName) {
                $targets = @(Get-ADUser -Identity $UserName `
                              -Properties AdminCount, DistinguishedName, MemberOf `
                              -Server $Domain -ErrorAction Stop)
            }
            else {
                # Tous les AdminCount=1 orphelins
                $allAdminCount = Get-ADUser -Filter { AdminCount -eq 1 } `
                                 -Properties AdminCount, DistinguishedName, MemberOf `
                                 -Server $Domain -ErrorAction Stop

                $tier0Groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins',
                                 'Administrators', 'Account Operators', 'Backup Operators')

                foreach ($user in $allAdminCount) {
                    $isProtected = $false
                    foreach ($grp in $tier0Groups) {
                        try {
                            $members = Get-ADGroupMember $grp -Recursive -Server $Domain -ErrorAction SilentlyContinue
                            if ($members | Where-Object SamAccountName -eq $user.SamAccountName) {
                                $isProtected = $true; break
                            }
                        }
                        catch {}
                    }
                    if (-not $isProtected) { $targets += $user }
                }
            }

            Write-Host "  Comptes AdminCount=1 orphelins cibles : $($targets.Count)" -ForegroundColor White
            Write-Host ""

            foreach ($user in $targets) {
                if ($user.AdminCount -ne 1) {
                    Write-Host "  [SKIP] $($user.SamAccountName) : AdminCount != 1" -ForegroundColor Gray
                    continue
                }

                Write-Host "  Cible : $($user.SamAccountName)" -ForegroundColor White
                Write-Host "  Impact : AdminCount sera remis a 0. Les ACL restrictives placees par AdminSDHolder" -ForegroundColor Yellow
                Write-Host "           seront restaurees a la valeur par defaut au prochain cycle SDProp (60 min)." -ForegroundColor Yellow
                Write-Host ""

                $action = "Remettre AdminCount=0 sur [$($user.SamAccountName)] - restauration des ACL par defaut au prochain cycle SDProp"

                if ($PSCmdlet.ShouldProcess($user.SamAccountName, $action)) {
                    try {
                        Set-ADUser -Identity $user.SamAccountName `
                                   -Replace @{ AdminCount = 0 } `
                                   -Server $Domain -ErrorAction Stop
                        Write-Host "  [OK] AdminCount = 0 sur [$($user.SamAccountName)]" -ForegroundColor Green
                        Write-Host "  [INFO] Les ACL seront normalisees au prochain run SDProp (toutes les 60 min)" -ForegroundColor Gray
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
        Write-Host "  [WHATIF] Simulation terminee. Aucune modification appliquee." -ForegroundColor Yellow
        Write-Host "  Relancer sans -WhatIf pour appliquer les corrections." -ForegroundColor Yellow
    }
    Write-Host ""
}
