function Find-DangerousDelegation {
    <#
    .SYNOPSIS
        Detecte les configurations de delegation Kerberos dangereuses.

    .DESCRIPTION
        Recherche trois types de delegations a risque :
        1. Unconstrained Delegation (TrustedForDelegation) sur comptes ordinateur et utilisateur
        2. Constrained Delegation avec protocol transition (TrustedToAuthForDelegation)
        3. Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
        Cible specifiquement le compte svc-plurihotel.

        MITRE ATT&CK : T1558.001 (Kerberos Golden Ticket), T1550.003 (Pass the Ticket)

    .PARAMETER Domain
        FQDN du domaine AD a analyser.

    .OUTPUTS
        PSCustomObject avec les champs : Category, FindingID, FindingName, Object,
        ObjectType, Risk, Severity, MitreRef, Description, AttackPath, Recommendation

    .EXAMPLE
        Find-DangerousDelegation -Domain mogador.local
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $findingIdCounter = 1

    # Comptes DC legitimes a exclure de l'unconstrained delegation
    # (les DC ont TrustedForDelegation=true par conception)
    $domainControllers = @()
    try {
        $domainControllers = (Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop).Name
    }
    catch {
        Write-Warning "[Find-Delegation] Impossible de recuperer la liste des DC : $_"
    }

    #region --- CHECK 1 : Unconstrained Delegation sur Ordinateurs ---

    Write-Verbose "[Find-Delegation] Verification Unconstrained Delegation sur comptes ordinateurs..."
    try {
        $computers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, OperatingSystem, Description, DistinguishedName `
            -Server $Domain -ErrorAction Stop

        foreach ($computer in $computers) {
            # Exclure les DCs (comportement normal)
            if ($computer.Name -in $domainControllers) {
                Write-Verbose "   [SKIP] $($computer.Name) est un DC - exclusion normale"
                continue
            }

            $findings.Add([PSCustomObject]@{
                Category       = 'Delegation'
                FindingID      = "DEL-$('{0:D3}' -f $findingIdCounter++)"
                FindingName    = 'Unconstrained Delegation - Compte Ordinateur'
                Object         = $computer.Name
                ObjectDN       = $computer.DistinguishedName
                ObjectType     = 'Computer'
                Risk           = 'Un attaquant compromettant ce poste peut capturer les TGT de tout utilisateur qui s y authentifie, y compris des Domain Admins.'
                Severity       = 'Critique'
                MitreRef       = 'T1558 / T1550.003'
                Description    = "Le compte ordinateur [$($computer.Name)] a TrustedForDelegation=True (Unconstrained Delegation). Ce n'est pas un DC, donc cette configuration est anormale et extremement dangereuse. Un attaquant avec acces local peut utiliser Rubeus ou Mimikatz pour extraire les tickets TGT mis en cache."
                AttackPath     = "Compromission de [$($computer.Name)] → PrinterBug/PetitPotam pour forcer une auth → Extraction TGT Domain Admin avec Rubeus → DCSync ou acces total au domaine"
                Recommendation = "Desactiver la delegation non contrainte : Set-ADComputer '$($computer.Name)' -TrustedForDelegation `$false. Utiliser Repair-DangerousDelegation -ObjectName '$($computer.Name)' -ObjectType Computer -WhatIf"
                OperatingSystem = $computer.OperatingSystem
                CanRemediate   = $true
            })
        }
    }
    catch {
        Write-Warning "[Find-Delegation] Erreur lors de la recherche Unconstrained Delegation (Computers) : $_"
    }

    #endregion

    #region --- CHECK 2 : Unconstrained Delegation sur Utilisateurs ---

    Write-Verbose "[Find-Delegation] Verification Unconstrained Delegation sur comptes utilisateurs..."
    try {
        $users = Get-ADUser -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, PasswordLastSet, LastLogonDate,
                        ServicePrincipalName, Description, DistinguishedName `
            -Server $Domain -ErrorAction Stop

        foreach ($user in $users) {
            # Detecter specifiquement svc-plurihotel
            $isSvcPlurihotel = ($user.SamAccountName -like 'svc-plurihotel*' -or
                                $user.Name -like '*plurihotel*')

            $findings.Add([PSCustomObject]@{
                Category       = 'Delegation'
                FindingID      = "DEL-$('{0:D3}' -f $findingIdCounter++)"
                FindingName    = if ($isSvcPlurihotel) { 'Unconstrained Delegation - svc-plurihotel [CIBLE CONNUE]' } else { 'Unconstrained Delegation - Compte Utilisateur' }
                Object         = $user.SamAccountName
                ObjectDN       = $user.DistinguishedName
                ObjectType     = 'User'
                Risk           = 'Delegation non contrainte sur un compte utilisateur/service permet de capturer n importe quel TGT qui se presente a ce compte.'
                Severity       = 'Critique'
                MitreRef       = 'T1558 / T1550.003'
                Description    = "Le compte utilisateur [$($user.SamAccountName)] a TrustedForDelegation=True. $(if ($isSvcPlurihotel) { 'ATTENTION : Il s agit du compte de service PMS svc-plurihotel, specifiquement identifie lors de l audit. ' })Dernier changement de mdp : $($user.PasswordLastSet). SPNs : $($user.ServicePrincipalName -join ', ')"
                AttackPath     = "Compromission du service sur [$($user.SamAccountName)] → Attente d une auth DA → Extraction TGT via Rubeus monitor → Pass-the-Ticket → DCSync"
                Recommendation = "Desactiver la delegation non contrainte. Si ce compte a besoin de delegation, migrer vers Constrained Delegation sur les services specifiques uniquement. Repair-DangerousDelegation -ObjectName '$($user.SamAccountName)' -ObjectType User -WhatIf"
                PasswordLastSet = $user.PasswordLastSet
                CanRemediate   = $true
            })
        }
    }
    catch {
        Write-Warning "[Find-Delegation] Erreur lors de la recherche Unconstrained Delegation (Users) : $_"
    }

    #endregion

    #region --- CHECK 3 : Constrained Delegation avec Protocol Transition ---

    Write-Verbose "[Find-Delegation] Verification Constrained Delegation avec Protocol Transition..."
    try {
        # TrustedToAuthForDelegation = "Use any authentication protocol" = Protocol Transition
        $usersKCD = Get-ADUser -Filter { TrustedToAuthForDelegation -eq $true } `
            -Properties TrustedToAuthForDelegation, 'msDS-AllowedToDelegateTo',
                        ServicePrincipalName, PasswordLastSet, DistinguishedName `
            -Server $Domain -ErrorAction Stop

        foreach ($user in $usersKCD) {
            $targetServices = $user.'msDS-AllowedToDelegateTo' -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Delegation'
                FindingID      = "DEL-$('{0:D3}' -f $findingIdCounter++)"
                FindingName    = 'Constrained Delegation avec Protocol Transition - Utilisateur'
                Object         = $user.SamAccountName
                ObjectDN       = $user.DistinguishedName
                ObjectType     = 'User'
                Risk           = 'Protocol Transition permet a ce compte d usurper l identite de N IMPORTE quel utilisateur (y compris DA) vers les services cibles, sans connaitre leur mot de passe.'
                Severity       = 'Eleve'
                MitreRef       = 'T1558.001'
                Description    = "[$($user.SamAccountName)] peut se faire passer pour n importe quel utilisateur vers : $targetServices. Le flag TrustedToAuthForDelegation active S4U2Self, permettant l obtention d un ST pour n importe quel principal, puis S4U2Proxy vers les services cibles."
                AttackPath     = "Compromission de [$($user.SamAccountName)] → S4U2Self pour impersonifier DA → S4U2Proxy vers [$targetServices] → Acces avec privileges DA sur ces services"
                Recommendation = "Auditer si la Protocol Transition est vraiment necessaire. Si oui, s assurer que les services cibles ne donnent pas d acces critique. Sinon, basculer sur Constrained Delegation classique (Kerberos only)."
                DelegateTo     = $targetServices
                CanRemediate   = $true
            })
        }

        $computersKCD = Get-ADComputer -Filter { TrustedToAuthForDelegation -eq $true } `
            -Properties TrustedToAuthForDelegation, 'msDS-AllowedToDelegateTo', DistinguishedName `
            -Server $Domain -ErrorAction Stop

        foreach ($comp in $computersKCD) {
            if ($comp.Name -in $domainControllers) { continue }
            $targetServices = $comp.'msDS-AllowedToDelegateTo' -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Delegation'
                FindingID      = "DEL-$('{0:D3}' -f $findingIdCounter++)"
                FindingName    = 'Constrained Delegation avec Protocol Transition - Ordinateur'
                Object         = $comp.Name
                ObjectDN       = $comp.DistinguishedName
                ObjectType     = 'Computer'
                Risk           = 'Protocol Transition sur ordinateur permet l usurpation d identite vers les services cibles depuis toute session locale.'
                Severity       = 'Eleve'
                MitreRef       = 'T1558.001'
                Description    = "L ordinateur [$($comp.Name)] a Protocol Transition activee vers : $targetServices"
                AttackPath     = "Acces local sur [$($comp.Name)] → S4U2Self/S4U2Proxy → Impersonification DA vers [$targetServices]"
                Recommendation = "Verifier si cette configuration est intentionnelle. Desactiver TrustedToAuthForDelegation si non necessaire."
                DelegateTo     = $targetServices
                CanRemediate   = $true
            })
        }
    }
    catch {
        Write-Warning "[Find-Delegation] Erreur lors de la recherche Protocol Transition : $_"
    }

    #endregion

    #region --- CHECK 4 : LAPS Delegation mal configuree ---

    Write-Verbose "[Find-Delegation] Verification delegation LAPS..."
    try {
        # Chercher des GPO ou des comptes avec delegation sur ms-Mcs-AdmPwd
        $lapsUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
            -Properties ServicePrincipalName, 'msDS-AllowedToDelegateTo', DistinguishedName `
            -Server $Domain -ErrorAction Stop |
            Where-Object { $_.'msDS-AllowedToDelegateTo' -like '*cifs*' -or
                           $_.'msDS-AllowedToDelegateTo' -like '*ldap*' }

        foreach ($user in $lapsUsers) {
            $targetServices = $user.'msDS-AllowedToDelegateTo' -join ', '
            $findings.Add([PSCustomObject]@{
                Category       = 'Delegation'
                FindingID      = "DEL-$('{0:D3}' -f $findingIdCounter++)"
                FindingName    = 'Delegation potentiellement liee a LAPS - Verification requise'
                Object         = $user.SamAccountName
                ObjectDN       = $user.DistinguishedName
                ObjectType     = 'User'
                Risk           = 'Une delegation CIFS ou LDAP mal configuree peut permettre la lecture des mots de passe LAPS stockes dans ms-Mcs-AdmPwd.'
                Severity       = 'Eleve'
                MitreRef       = 'T1555'
                Description    = "[$($user.SamAccountName)] a une delegation vers des services CIFS/LDAP ($targetServices) qui peut interagir avec la lecture LAPS si les ACL ms-Mcs-AdmPwd ne sont pas correctement restreintes."
                AttackPath     = "Compromission de [$($user.SamAccountName)] → Delegation LDAP/CIFS → Lecture ms-Mcs-AdmPwd → Mot de passe admin local de toutes les machines gerees par LAPS"
                Recommendation = "Verifier les ACL sur l attribut ms-Mcs-AdmPwd dans l AD. S assurer que seuls les groupes autorises peuvent lire cet attribut. Auditer avec : Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd"
                DelegateTo     = $targetServices
                CanRemediate   = $false
            })
        }
    }
    catch {
        Write-Warning "[Find-Delegation] Erreur lors de la verification delegation LAPS : $_"
    }

    #endregion

    Write-Verbose "[Find-Delegation] Total findings delegation : $($findings.Count)"
    return $findings
}
