function Find-ACLAbuses {
    <#
    .SYNOPSIS
        Detecte les abus d'ACL sur les objets AD sensibles — MODE EXPLAIN ONLY.

    .DESCRIPTION
        Parcourt les ACL des objets Tier-0 (OU sensibles, groupes privilegies, GPO)
        et identifie les ACE dangereuses accordees a des principals non-attendus.

        !! IMPORTANT : Cette fonction NE PROPOSE PAS de remediation automatique !!
        La raison : une ACE GenericAll peut etre une delegation legitime (ex: Helpdesk
        avec WriteProperty pour le reset de mot de passe) ou une backdoor. Un script
        ne peut pas distinguer les deux sans comprendre l intention metier.
        La decision de retirer une ACE appartient a un humain.

        MITRE ATT&CK : T1222 (File/Directory Permissions), T1078 (Valid Accounts),
                        T1484.001 (GPO Modification)

    .PARAMETER Domain
        FQDN du domaine AD a analyser.

    .OUTPUTS
        PSCustomObject avec explication de la chaine d'attaque, sans commande de correction.

    .EXAMPLE
        Find-ACLAbuses -Domain mogador.local
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $findingIdCounter = 1

    # Droits AD consideres comme dangereux s'ils sont accordes a des non-admins
    $dangerousRights = @(
        'GenericAll',
        'GenericWrite',
        'WriteDacl',
        'WriteOwner',
        'AllExtendedRights',
        'WriteProperty'
    )

    # Principals "normaux" qui peuvent legitimement avoir des droits etendus
    # (exclus de l'alerte pour reduire les faux positifs)
    $expectedPrincipals = @(
        'Domain Admins',
        'Enterprise Admins',
        'SYSTEM',
        'Administrators',
        'Schema Admins',
        'CREATOR OWNER',
        'ENTERPRISE DOMAIN CONTROLLERS',
        'NT AUTHORITY',
        'BUILTIN'
    )

    # Helper : verifier si un identityReference est un principal "attendu"
    function Test-IsExpectedPrincipal {
        param([string]$Identity)
        foreach ($expected in $expectedPrincipals) {
            if ($Identity -like "*$expected*") { return $true }
        }
        return $false
    }

    # Helper : obtenir le DN du domaine
    function Get-DomainDN {
        param([string]$DomainFQDN)
        return "DC=" + ($DomainFQDN.Split('.') -join ',DC=')
    }

    $domainDN = Get-DomainDN -DomainFQDN $Domain

    #region --- CHECK 1 : ACL du groupe Domain Admins ---

    Write-Verbose "[Find-ACLAbuse] Analyse ACL de Domain Admins..."
    try {
        $daGroup = Get-ADGroup 'Domain Admins' -Server $Domain -Properties DistinguishedName -ErrorAction Stop
        $daPath  = "AD:\$($daGroup.DistinguishedName)"
        $daACL   = Get-Acl -Path $daPath -ErrorAction Stop

        foreach ($ace in $daACL.Access) {
            $rights  = $ace.ActiveDirectoryRights.ToString()
            $identity = $ace.IdentityReference.ToString()

            if (Test-IsExpectedPrincipal -Identity $identity) { continue }

            $isDangerous = $dangerousRights | Where-Object { $rights -like "*$_*" }
            if ($isDangerous) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'ACLAbuse'
                    FindingID      = "ACL-$('{0:D3}' -f $findingIdCounter++)"
                    FindingName    = "ACE dangereuse sur Domain Admins : $($isDangerous -join '+')"
                    Object         = 'Domain Admins'
                    ObjectDN       = $daGroup.DistinguishedName
                    ObjectType     = 'Group'
                    Risk           = "[$identity] a [$rights] sur Domain Admins. Cela peut permettre d ajouter un membre au groupe ou de modifier ses ACL."
                    Severity       = 'Critique'
                    MitreRef       = 'T1222 / T1078.002'
                    Description    = "ACE trouvee : [$identity] → [$rights] sur [$($daGroup.DistinguishedName)]. Type : $($ace.AccessControlType). Heritage : $($ace.IsInherited). Cette permission donne a [$identity] un controle potentiel sur le groupe Domain Admins."
                    AttackPath     = "Compromission d un compte membre de [$identity] → Utilisation de [$rights] sur Domain Admins → $(if ($rights -like '*GenericAll*' -or $rights -like '*WriteDacl*') { 'Modification des ACL du groupe ou ajout de membre' } elseif ($rights -like '*WriteOwner*') { 'Prise de propriete du groupe puis modification des ACL' } else { 'Modification du groupe' }) → Acces Domain Admin"
                    Recommendation = "[EXPLAIN ONLY] Auditer manuellement pourquoi [$identity] a [$rights] sur Domain Admins. Si non justifie, retirer l ACE via : (Get-Acl 'AD:\\$($daGroup.DistinguishedName)') puis Remove-AceAndSetAcl. NE PAS AUTOMATISER sans validation metier."
                    ACEIdentity    = $identity
                    ACERights      = $rights
                    IsInherited    = $ace.IsInherited
                    CanRemediate   = $false  # INTENTIONNEL - voir description du module
                })
            }
        }
    }
    catch {
        Write-Warning "[Find-ACLAbuse] Erreur analyse ACL Domain Admins : $_"
    }

    #endregion

    #region --- CHECK 2 : ACL sur la racine du domaine ---

    Write-Verbose "[Find-ACLAbuse] Analyse ACL racine du domaine ($domainDN)..."
    try {
        $domainACL = Get-Acl -Path "AD:\$domainDN" -ErrorAction Stop

        foreach ($ace in $domainACL.Access) {
            $rights   = $ace.ActiveDirectoryRights.ToString()
            $identity = $ace.IdentityReference.ToString()

            if (Test-IsExpectedPrincipal -Identity $identity) { continue }
            if ($ace.IsInherited) { continue }  # Ignorer les ACE heritees pour la racine

            $isDangerous = $dangerousRights | Where-Object {
                $rights -like "*GenericAll*" -or
                $rights -like "*WriteDacl*" -or
                $rights -like "*WriteOwner*"
            }

            if ($isDangerous) {
                $findings.Add([PSCustomObject]@{
                    Category       = 'ACLAbuse'
                    FindingID      = "ACL-$('{0:D3}' -f $findingIdCounter++)"
                    FindingName    = "ACE dangereuse sur la racine du domaine"
                    Object         = $domainDN
                    ObjectDN       = $domainDN
                    ObjectType     = 'Domain'
                    Risk           = "[$identity] a [$rights] sur la racine du domaine. Cela peut permettre DCSync, modification de GPO, ou prise de controle du domaine entier."
                    Severity       = 'Critique'
                    MitreRef       = 'T1222 / T1003.006 (DCSync)'
                    Description    = "ACE non-heritee sur la racine [$domainDN] : [$identity] → [$rights]. Un ACE GenericAll ou WriteDacl sur le domaine permet potentiellement l attaque DCSync (extraction de tous les hashes NTLM)."
                    AttackPath     = "Compromission de [$identity] → [$rights] sur le domaine → DCSync via secretsdump.py ou Mimikatz lsadump::dcsync → Tous les hashes NTLM du domaine"
                    Recommendation = "[EXPLAIN ONLY] Verifier manuellement cette ACE. L attaque DCSync necessite GetChanges + GetChangesAll sur le domaine. Auditer les comptes membres de [$identity]."
                    ACEIdentity    = $identity
                    ACERights      = $rights
                    IsInherited    = $ace.IsInherited
                    CanRemediate   = $false
                })
            }
        }
    }
    catch {
        Write-Warning "[Find-ACLAbuse] Erreur analyse ACL domaine : $_"
    }

    #endregion

    #region --- CHECK 3 : ACL sur les GPO sensibles ---

    Write-Verbose "[Find-ACLAbuse] Analyse ACL des GPO liees aux Tier-0..."
    try {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $gpos = Get-GPO -All -Domain $Domain -ErrorAction Stop

        # GPO considerees sensibles : Default Domain Policy, Default DC Policy, ou celles liees aux Admins
        $sensitiveGPOPatterns = @('Default Domain Policy', 'Default Domain Controllers Policy',
                                   'Domain Controller', 'Tier0', 'T0-', 'Admin')

        foreach ($gpo in $gpos) {
            $isSensitive = $sensitiveGPOPatterns | Where-Object { $gpo.DisplayName -like "*$_*" }
            if (-not $isSensitive) { continue }

            try {
                $gpoACL = Get-Acl -Path "AD:\CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN" -ErrorAction Stop

                foreach ($ace in $gpoACL.Access) {
                    $rights   = $ace.ActiveDirectoryRights.ToString()
                    $identity = $ace.IdentityReference.ToString()

                    if (Test-IsExpectedPrincipal -Identity $identity) { continue }

                    $isDangerous = $dangerousRights | Where-Object { $rights -like "*$_*" }
                    if ($isDangerous) {
                        $findings.Add([PSCustomObject]@{
                            Category       = 'ACLAbuse'
                            FindingID      = "ACL-$('{0:D3}' -f $findingIdCounter++)"
                            FindingName    = "ACE dangereuse sur GPO sensible : $($gpo.DisplayName)"
                            Object         = $gpo.DisplayName
                            ObjectDN       = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN"
                            ObjectType     = 'GPO'
                            Risk           = "[$identity] peut modifier la GPO [$($gpo.DisplayName)]. Une GPO compromise peut deployer des scripts malveillants sur toutes les machines qu elle couvre."
                            Severity       = 'Critique'
                            MitreRef       = 'T1484.001 (GPO Modification)'
                            Description    = "[$identity] a [$rights] sur la GPO [$($gpo.DisplayName)] (ID: $($gpo.Id)). Les GPO Tier-0 ne doivent etre modifiables que par Domain Admins et SYSTEM."
                            AttackPath     = "Compromission de [$identity] → Modification de la GPO [$($gpo.DisplayName)] → Deploiement de script malveillant (ex: ajout d un DA local, collecte de credentials) → Execution sur toutes les machines dans le perimetre de la GPO"
                            Recommendation = "[EXPLAIN ONLY] Verifier les permissions de la GPO [$($gpo.DisplayName)] dans la console GPMC. Comparer avec les permissions attendues. Si suspect, retirer l ACE apres validation metier."
                            GPOName        = $gpo.DisplayName
                            GPOID          = $gpo.Id.ToString()
                            ACEIdentity    = $identity
                            ACERights      = $rights
                            CanRemediate   = $false
                        })
                    }
                }
            }
            catch {
                Write-Verbose "[Find-ACLAbuse] Impossible d analyser ACL GPO $($gpo.DisplayName) : $_"
            }
        }
    }
    catch {
        Write-Warning "[Find-ACLAbuse] Erreur analyse GPO : $_"
    }

    #endregion

    #region --- CHECK 4 : ACL sur les OU sensibles ---

    Write-Verbose "[Find-ACLAbuse] Analyse ACL des OU sensibles..."
    try {
        # OU contenant des comptes privilegies ou des serveurs Tier-0
        $sensitiveOUPatterns = @('Domain Controllers', 'Admin', 'Tier0', 'T0-',
                                  'Servers', 'Privileged', 'Security')

        $allOUs = Get-ADOrganizationalUnit -Filter * -Server $Domain `
                  -Properties DistinguishedName, Name -ErrorAction Stop

        foreach ($ou in $allOUs) {
            $isSensitive = $sensitiveOUPatterns | Where-Object { $ou.Name -like "*$_*" }
            if (-not $isSensitive) { continue }

            try {
                $ouACL = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction Stop

                foreach ($ace in $ouACL.Access) {
                    $rights   = $ace.ActiveDirectoryRights.ToString()
                    $identity = $ace.IdentityReference.ToString()

                    if (Test-IsExpectedPrincipal -Identity $identity) { continue }
                    if ($ace.IsInherited) { continue }

                    if ($rights -like '*GenericAll*' -or $rights -like '*WriteDacl*' -or $rights -like '*WriteOwner*') {
                        $findings.Add([PSCustomObject]@{
                            Category       = 'ACLAbuse'
                            FindingID      = "ACL-$('{0:D3}' -f $findingIdCounter++)"
                            FindingName    = "ACE dangereuse sur OU sensible : $($ou.Name)"
                            Object         = $ou.Name
                            ObjectDN       = $ou.DistinguishedName
                            ObjectType     = 'OrganizationalUnit'
                            Risk           = "[$identity] a [$rights] sur l OU [$($ou.Name)]. Cela peut permettre de modifier les objets contenus dans cette OU (comptes, GPO liees, etc.)."
                            Severity       = 'Eleve'
                            MitreRef       = 'T1222'
                            Description    = "ACE non heritee : [$identity] → [$rights] sur l OU [$($ou.DistinguishedName)]. Une permission GenericAll sur une OU contenant des comptes admin ou des serveurs Tier-0 est particulierement dangereuse."
                            AttackPath     = "Compromission de [$identity] → [$rights] sur OU [$($ou.Name)] → Modification/suppression de comptes ou liaison de GPO malveillante → Acces aux systemes Tier-0 de cette OU"
                            Recommendation = "[EXPLAIN ONLY] Verifier manuellement cette ACE dans ADUC (Affichage > Fonctionnalites avancees > Securite). Comparer avec les permissions attendues pour cette OU."
                            ACEIdentity    = $identity
                            ACERights      = $rights
                            IsInherited    = $ace.IsInherited
                            CanRemediate   = $false
                        })
                    }
                }
            }
            catch {
                Write-Verbose "[Find-ACLAbuse] Impossible d analyser OU $($ou.Name)"
            }
        }
    }
    catch {
        Write-Warning "[Find-ACLAbuse] Erreur analyse OU : $_"
    }

    #endregion

    Write-Verbose "[Find-ACLAbuse] Total findings ACL : $($findings.Count)"
    Write-Verbose "[Find-ACLAbuse] RAPPEL : Ce module est EXPLAIN-ONLY. Aucune remediation automatique."
    return $findings
}
