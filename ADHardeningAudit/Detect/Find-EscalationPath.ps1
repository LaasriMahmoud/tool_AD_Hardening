function Find-PrivilegeEscalationPaths {
    <#
    .SYNOPSIS
        Detecte les chemins d'escalade de privileges dans l'AD.

    .DESCRIPTION
        Analyse trois vecteurs d'escalade :
        1. Nesting de groupes menant a Domain Admins / Enterprise Admins (cible : IT-Support)
        2. Comptes avec AdminCount=1 qui ne sont plus membres d'un groupe protege (orphelins SDProp)
        3. Groupes imbriques dans les groupes Tier-0 avec des membres inattendus

        MITRE ATT&CK : T1078.002 (Domain Accounts), T1484 (Domain Policy Modification)

    .PARAMETER Domain
        FQDN du domaine AD a analyser.

    .OUTPUTS
        PSCustomObject avec les champs standards de finding.

    .EXAMPLE
        Find-PrivilegeEscalationPaths -Domain mogador.local
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $findingIdCounter = 1

    # Groupes Tier-0 a surveiller
    $tier0Groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins',
                     'Administrators', 'Group Policy Creator Owners',
                     'Account Operators', 'Backup Operators', 'Print Operators',
                     'Server Operators', 'Remote Management Users')

    # Groupes dont les membres DIRECTS sont attendus (hors nesting)
    $expectedDirectGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins',
                               'SYSTEM', 'Administrator')

    #region --- CHECK 1 : Nesting de groupes vers Tier-0 ---

    Write-Verbose "[Find-EscalationPath] Analyse du nesting de groupes vers les groupes Tier-0..."

    foreach ($groupName in $tier0Groups) {
        try {
            # Membres directs (non recursifs)
            $directMembers = @()
            try {
                $directMembers = Get-ADGroupMember -Identity $groupName -Server $Domain -ErrorAction Stop
            }
            catch { continue }

            # Membres recursifs complets
            $allMembers = @()
            try {
                $allMembers = Get-ADGroupMember -Identity $groupName -Recursive -Server $Domain -ErrorAction Stop
            }
            catch { $allMembers = $directMembers }

            # Identifier les groupes imbriques (membres directs de type Group)
            $nestedGroups = $directMembers | Where-Object { $_.objectClass -eq 'group' }

            foreach ($nestedGroup in $nestedGroups) {
                # Evaluer si c'est le groupe IT-Support specifiquement
                $isITSupport = ($nestedGroup.Name -like '*IT-Support*' -or
                                $nestedGroup.SamAccountName -like '*IT-Support*')

                # Recuperer les membres du groupe imbrique
                $nestedMembers = @()
                try {
                    $nestedMembers = Get-ADGroupMember -Identity $nestedGroup.DistinguishedName `
                                    -Server $Domain -ErrorAction Stop
                }
                catch {}

                $nestedMembersStr = ($nestedMembers | Select-Object -ExpandProperty Name) -join ', '

                $findings.Add([PSCustomObject]@{
                    Category       = 'EscalationPath'
                    FindingID      = "ESC-$('{0:D3}' -f $findingIdCounter++)"
                    FindingName    = if ($isITSupport) {
                                        "Nesting dangereux : IT-Support → $groupName [CIBLE CONNUE]"
                                    } else {
                                        "Nesting de groupe vers $groupName"
                                    }
                    Object         = $nestedGroup.Name
                    ObjectDN       = $nestedGroup.DistinguishedName
                    ObjectType     = 'Group'
                    Risk           = "Les membres du groupe [$($nestedGroup.Name)] heritent des privileges de [$groupName] via le nesting. Ce chemin est souvent oublie lors de l audit des privileges."
                    Severity       = if ($groupName -in @('Domain Admins','Enterprise Admins','Administrators')) { 'Critique' } else { 'Eleve' }
                    MitreRef       = 'T1078.002'
                    Description    = "Le groupe [$($nestedGroup.Name)] est membre DIRECT de [$groupName]. Ses membres ($($nestedMembers.Count) au total) heritent donc de tous les privileges de [$groupName]. $(if ($isITSupport) { 'ATTENTION : IT-Support identifie comme vecteur d escalade lors de l audit initial !' }) Membres du groupe imbrique : $nestedMembersStr"
                    AttackPath     = "Compromission d un compte membre de [$($nestedGroup.Name)] → Privileges [$groupName] herites automatiquement → Controle complet du domaine si [$groupName] = Domain Admins"
                    Recommendation = "Retirer [$($nestedGroup.Name)] de [$groupName] si ce nesting n est pas justifie. Utiliser des groupes de securite plats pour les privileges Tier-0. Repair-EscalationPaths -NestedGroup '$($nestedGroup.Name)' -ParentGroup '$groupName' -WhatIf"
                    ParentGroup    = $groupName
                    NestedMembers  = $nestedMembersStr
                    NestedCount    = $nestedMembers.Count
                    CanRemediate   = $true
                })
            }

            # Checker aussi les utilisateurs directs qui semblent inhabituels
            $directUsers = $directMembers | Where-Object { $_.objectClass -eq 'user' }
            if ($directUsers.Count -gt 5 -and $groupName -eq 'Domain Admins') {
                $findings.Add([PSCustomObject]@{
                    Category       = 'EscalationPath'
                    FindingID      = "ESC-$('{0:D3}' -f $findingIdCounter++)"
                    FindingName    = "Trop de membres directs dans $groupName"
                    Object         = $groupName
                    ObjectDN       = (Get-ADGroup $groupName -Server $Domain).DistinguishedName
                    ObjectType     = 'Group'
                    Risk           = "Un grand nombre de membres directs dans Domain Admins augmente massivement la surface d attaque."
                    Severity       = 'Eleve'
                    MitreRef       = 'T1078.002'
                    Description    = "[$groupName] contient $($directUsers.Count) utilisateurs directs. Bonne pratique : max 5 comptes dedies, jamais de comptes de service. Membres : $(($directUsers | Select-Object -First 10 | Select-Object -ExpandProperty Name) -join ', ')..."
                    AttackPath     = "Compromission de n importe lequel des $($directUsers.Count) comptes → Acces Domain Admin direct"
                    Recommendation = "Reduire le nombre de membres Domain Admins. Utiliser des comptes dedies (PAW) pour l administration. Retirer les comptes de service et les comptes utilisateurs quotidiens."
                    CanRemediate   = $false
                })
            }
        }
        catch {
            Write-Warning "[Find-EscalationPath] Erreur analyse groupe $groupName : $_"
        }
    }

    #endregion

    #region --- CHECK 2 : AdminCount orphelins ---

    Write-Verbose "[Find-EscalationPath] Recherche des comptes AdminCount=1 orphelins..."
    try {
        $adminCountUsers = Get-ADUser -Filter { AdminCount -eq 1 } `
            -Properties AdminCount, MemberOf, PasswordLastSet, LastLogonDate,
                        DistinguishedName, Enabled `
            -Server $Domain -ErrorAction Stop

        foreach ($user in $adminCountUsers) {
            # Verifier s'il est encore membre d'un groupe protege
            $isInProtectedGroup = $false
            $protectedGroupsDN = @()

            foreach ($tier0 in $tier0Groups) {
                try {
                    $members = Get-ADGroupMember -Identity $tier0 -Recursive -Server $Domain -ErrorAction SilentlyContinue
                    if ($members | Where-Object { $_.SamAccountName -eq $user.SamAccountName }) {
                        $isInProtectedGroup = $true
                        $protectedGroupsDN += $tier0
                        break
                    }
                }
                catch {}
            }

            if (-not $isInProtectedGroup) {
                # AdminCount=1 mais plus dans aucun groupe protege = orphelin SDProp
                $findings.Add([PSCustomObject]@{
                    Category        = 'EscalationPath'
                    FindingID       = "ESC-$('{0:D3}' -f $findingIdCounter++)"
                    FindingName     = 'AdminCount=1 orphelin (SDProp residuel)'
                    Object          = $user.SamAccountName
                    ObjectDN        = $user.DistinguishedName
                    ObjectType      = 'User'
                    Risk            = 'Ce compte avait autrefois des privileges eleves (AdminCount=1 positionne par AdminSDHolder). Il n en a plus, mais ses ACL ont peut-etre ete restrictivement modifiees et il peut retenir des droits residuels caches.'
                    Severity        = 'Moyen'
                    MitreRef        = 'T1078.002'
                    Description     = "[$($user.SamAccountName)] a AdminCount=1 mais n est plus membre d aucun groupe protege Tier-0. Cela signifie qu il avait autrefois des privileges eleves et que l AdminSDHolder a protege ses ACL. Ces restrictions persistent et peuvent masquer des droits residuels. Dernier login : $($user.LastLogonDate). Actif : $($user.Enabled)"
                    AttackPath      = "Exploitation des ACL residuelles sur [$($user.SamAccountName)] → Potentiel acces a des ressources Tier-0 non inventoriees"
                    Recommendation  = "1. Remettre AdminCount a 0 : Set-ADUser '$($user.SamAccountName)' -Replace @{AdminCount=0}. 2. Regenerer les ACL par defaut sur l objet. 3. Auditer pourquoi ce compte avait des privileges eleves."
                    PasswordLastSet = $user.PasswordLastSet
                    LastLogonDate   = $user.LastLogonDate
                    Enabled         = $user.Enabled
                    CanRemediate    = $true
                })
            }
        }
    }
    catch {
        Write-Warning "[Find-EscalationPath] Erreur recherche AdminCount orphelins : $_"
    }

    #endregion

    #region --- CHECK 3 : Groupes privilegies avec members non-humains ---

    Write-Verbose "[Find-EscalationPath] Recherche de comptes de service dans les groupes Tier-0..."
    try {
        $daMembers = Get-ADGroupMember -Identity 'Domain Admins' -Recursive `
                     -Server $Domain -ErrorAction Stop

        foreach ($member in $daMembers) {
            if ($member.objectClass -eq 'user') {
                # Chercher les patterns de comptes de service
                if ($member.SamAccountName -match '^svc[-_]|[-_]svc$|^service|_srv$|^srv[-_]') {
                    $userProps = Get-ADUser $member.DistinguishedName `
                                 -Properties PasswordLastSet, PasswordNeverExpires, `
                                             ServicePrincipalName, DistinguishedName `
                                 -Server $Domain -ErrorAction SilentlyContinue

                    $findings.Add([PSCustomObject]@{
                        Category            = 'EscalationPath'
                        FindingID           = "ESC-$('{0:D3}' -f $findingIdCounter++)"
                        FindingName         = 'Compte de service membre de Domain Admins'
                        Object              = $member.SamAccountName
                        ObjectDN            = $member.DistinguishedName
                        ObjectType          = 'User'
                        Risk                = 'Un compte de service dans Domain Admins est une cible Kerberoastable avec privileges maximaux. Sa compromission = compromission totale du domaine.'
                        Severity            = 'Critique'
                        MitreRef            = 'T1078.002 / T1558.003'
                        Description         = "Le compte [$($member.SamAccountName)] ressemble a un compte de service (pattern SVC/SRV) et est membre de Domain Admins. Dernier mdp : $($userProps.PasswordLastSet). SPNs : $($userProps.ServicePrincipalName -join ', ')"
                        AttackPath          = "Kerberoasting de [$($member.SamAccountName)] → Crack mdp service → Acces Domain Admin direct"
                        Recommendation      = "Retirer immediatement ce compte de service de Domain Admins. Les comptes de service ne doivent jamais etre membres de groupes Tier-0. Utiliser des gMSA avec des permissions minimales."
                        SPNs                = $userProps.ServicePrincipalName -join ' | '
                        PasswordLastSet     = $userProps.PasswordLastSet
                        PasswordNeverExpires = $userProps.PasswordNeverExpires
                        CanRemediate        = $true
                    })
                }
            }
        }
    }
    catch {
        Write-Warning "[Find-EscalationPath] Erreur analyse membres Domain Admins : $_"
    }

    #endregion

    Write-Verbose "[Find-EscalationPath] Total findings escalation : $(@($Findings).Count)"
    return $findings
}
