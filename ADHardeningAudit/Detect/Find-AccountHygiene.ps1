function Find-AccountHygieneIssues {
    <#
    .SYNOPSIS
        Detecte les problemes d'hygiene des comptes Active Directory.

    .DESCRIPTION
        Effectue 4 verifications d'hygiene :
        1. Comptes AS-REP Roastable (DoesNotRequirePreAuth)
        2. Comptes Kerberoastable avec mot de passe vieux (SPN + PasswordLastSet > 180j)
        3. Comptes inactifs/stale (LastLogonTimestamp > 90j et actives)
        4. Comptes avec chiffrement reversible des mots de passe

        MITRE ATT&CK : T1558.004 (AS-REP Roasting), T1558.003 (Kerberoasting)

    .PARAMETER Domain
        FQDN du domaine AD a analyser.

    .PARAMETER StaleThresholdDays
        Nombre de jours d inactivite avant qu un compte soit considere stale. Default : 90

    .PARAMETER PasswordAgeDays
        Age maximal acceptable d un mot de passe de service (jours). Default : 180

    .OUTPUTS
        PSCustomObject avec les champs standards de finding.

    .EXAMPLE
        Find-AccountHygieneIssues -Domain mogador.local -StaleThresholdDays 90
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(Mandatory = $false)]
        [int]$StaleThresholdDays = 90,

        [Parameter(Mandatory = $false)]
        [int]$PasswordAgeDays = 180
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $findingIdCounter = 1
    $staleDate   = (Get-Date).AddDays(-$StaleThresholdDays)
    $pwdStaleDate = (Get-Date).AddDays(-$PasswordAgeDays)

    #region --- CHECK 1 : AS-REP Roasting (DoesNotRequirePreAuth) ---

    Write-Verbose "[Find-AccountHygiene] Recherche des comptes AS-REP Roastable..."
    try {
        $asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties DoesNotRequirePreAuth, PasswordLastSet, LastLogonDate,
                        ServicePrincipalName, MemberOf, DistinguishedName, Description `
            -Server $Domain -ErrorAction Stop

        foreach ($user in $asrepUsers) {
            # Evaluer la gravite : membre de groupes privilegies = Critique
            $isPrivileged = $false
            foreach ($group in $user.MemberOf) {
                if ($group -match 'Domain Admins|Enterprise Admins|Administrators|Schema Admins') {
                    $isPrivileged = $true; break
                }
            }

            $findings.Add([PSCustomObject]@{
                Category        = 'AccountHygiene'
                FindingID       = "HYG-$('{0:D3}' -f $findingIdCounter++)"
                FindingName     = 'AS-REP Roasting - Pre-authentification Kerberos desactivee'
                Object          = $user.SamAccountName
                ObjectDN        = $user.DistinguishedName
                ObjectType      = 'User'
                Risk            = 'Sans pre-authentification, n importe qui peut demander un AS-REP chiffre avec le hash du mot de passe de ce compte et le cracker hors-ligne avec hashcat ou john.'
                Severity        = if ($isPrivileged) { 'Critique' } else { 'Eleve' }
                MitreRef        = 'T1558.004'
                Description     = "[$($user.SamAccountName)] a DoesNotRequirePreAuth=True. Dernier mdp : $($user.PasswordLastSet). Dernier login : $($user.LastLogonDate). $(if ($isPrivileged) { 'CRITIQUE : Ce compte est membre d un groupe privilegie !' })"
                AttackPath      = "GetNPUsers.py mogador.local/$($user.SamAccountName) → Obtention hash AS-REP → hashcat -m 18200 hash.txt wordlist.txt → Mot de passe en clair → Acces compte"
                Recommendation  = "Reactiver la pre-authentification : Set-ADUser '$($user.SamAccountName)' -DoesNotRequirePreAuth `$false. Utiliser Repair-AccountHygieneIssues -Type ASREP -WhatIf"
                PasswordLastSet = $user.PasswordLastSet
                LastLogonDate   = $user.LastLogonDate
                IsPrivileged    = $isPrivileged
                CanRemediate    = $true
            })
        }
    }
    catch {
        Write-Warning "[Find-AccountHygiene] Erreur recherche AS-REP : $_"
    }

    #endregion

    #region --- CHECK 2 : Kerberoasting (SPN + mot de passe vieux) ---

    Write-Verbose "[Find-AccountHygiene] Recherche des comptes Kerberoastable..."
    try {
        $kerbUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' -and Enabled -eq $true } `
            -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate,
                        MemberOf, DistinguishedName, Description, PasswordNeverExpires `
            -Server $Domain -ErrorAction Stop

        foreach ($user in $kerbUsers) {
            # Exclure krbtgt
            if ($user.SamAccountName -eq 'krbtgt') { continue }

            $isSvcPlurihotel = ($user.SamAccountName -like 'svc-plurihotel*' -or $user.Name -like '*plurihotel*')
            $pwdIsOld = ($null -eq $user.PasswordLastSet) -or ($user.PasswordLastSet -lt $pwdStaleDate)
            $neverExpires = $user.PasswordNeverExpires

            # Un compte Kerberoastable est toujours a signaler, mais la severite monte si le mdp est vieux
            $severity = if ($isSvcPlurihotel) { 'Critique' }
                        elseif ($pwdIsOld) { 'Eleve' }
                        else { 'Moyen' }

            $findings.Add([PSCustomObject]@{
                Category           = 'AccountHygiene'
                FindingID          = "HYG-$('{0:D3}' -f $findingIdCounter++)"
                FindingName        = if ($isSvcPlurihotel) { 'Kerberoasting - svc-plurihotel [CIBLE CONNUE]' } else { 'Kerberoasting - Compte de service avec SPN' }
                Object             = $user.SamAccountName
                ObjectDN           = $user.DistinguishedName
                ObjectType         = 'User'
                Risk               = 'Tout utilisateur authentifie peut demander un TGS pour ce service. Le ticket est chiffre avec le hash du compte et crackable hors-ligne.'
                Severity           = $severity
                MitreRef           = 'T1558.003'
                Description        = "[$($user.SamAccountName)] a les SPNs : $($user.ServicePrincipalName -join ' | '). Dernier mdp : $(if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'JAMAIS' }). Mdp expire : $(-not $neverExpires). $(if ($isSvcPlurihotel) { 'ATTENTION : Compte PMS svc-plurihotel identifie lors de l audit !' })"
                AttackPath         = "GetUserSPNs.py mogador.local/$($user.SamAccountName) -request → Hash TGS → hashcat -m 13100 → Mot de passe service → Potentiellement acces a des systemes avec ce compte"
                Recommendation     = "Changer le mot de passe de ce compte de service immediatement si > $PasswordAgeDays jours. Envisager les Managed Service Accounts (gMSA) pour rotation automatique. Ne pas attribuer de SPN a des comptes utilisateur ordinaires."
                SPNs               = $user.ServicePrincipalName -join ' | '
                PasswordLastSet    = $user.PasswordLastSet
                PasswordNeverExpires = $neverExpires
                PasswordIsOld      = $pwdIsOld
                IsSvcPlurihotel    = $isSvcPlurihotel
                CanRemediate       = $false  # On ne change pas automatiquement un mdp de service
            })
        }
    }
    catch {
        Write-Warning "[Find-AccountHygiene] Erreur recherche Kerberoasting : $_"
    }

    #endregion

    #region --- CHECK 3 : Comptes stale (inactifs) ---

    Write-Verbose "[Find-AccountHygiene] Recherche des comptes inactifs (stale)..."
    try {
        # LastLogonTimestamp est replique toutes les 14 jours - valeur approchee
        $staleUsers = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $staleDate } `
            -Properties LastLogonDate, PasswordLastSet, Created,
                        MemberOf, DistinguishedName, Description `
            -Server $Domain -ErrorAction Stop

        # Aussi les comptes actives mais jamais connectes depuis plus de staleThreshold jours
        $neverLoggedIn = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -notlike '*' } `
            -Properties LastLogonDate, Created, DistinguishedName `
            -Server $Domain -ErrorAction Stop |
            Where-Object { $_.Created -lt $staleDate }

        $allStale = @($staleUsers) + @($neverLoggedIn) | Select-Object -Unique -Property *

        foreach ($user in $allStale) {
            $daysSinceLogin = if ($user.LastLogonDate) {
                [Math]::Round(((Get-Date) - $user.LastLogonDate).TotalDays)
            } else { 'Jamais connecte' }

            $findings.Add([PSCustomObject]@{
                Category        = 'AccountHygiene'
                FindingID       = "HYG-$('{0:D3}' -f $findingIdCounter++)"
                FindingName     = 'Compte inactif (Stale Account)'
                Object          = $user.SamAccountName
                ObjectDN        = $user.DistinguishedName
                ObjectType      = 'User'
                Risk            = 'Les comptes inactifs sont des cibles privilegiees pour les attaquants : credential stuffing, acces non monitore, potentiel pivot lateral.'
                Severity        = 'Moyen'
                MitreRef        = 'T1078 (Valid Accounts)'
                Description     = "[$($user.SamAccountName)] est actif mais inactif depuis $daysSinceLogin jours (seuil : $StaleThresholdDays j). Cree le : $($user.Created). Dernier login : $($user.LastLogonDate)"
                AttackPath      = "Credential stuffing / password spray sur [$($user.SamAccountName)] → Connexion non detectee → Pivot lateral depuis compte legitime"
                Recommendation  = "Desactiver le compte si l utilisateur n est plus dans l organisation : Disable-ADAccount '$($user.SamAccountName)'. Utiliser Repair-AccountHygieneIssues -Type Stale -WhatIf"
                LastLogonDate   = $user.LastLogonDate
                DaysSinceLogin  = $daysSinceLogin
                Created         = $user.Created
                CanRemediate    = $true
            })
        }
    }
    catch {
        Write-Warning "[Find-AccountHygiene] Erreur recherche comptes stale : $_"
    }

    #endregion

    #region --- CHECK 4 : Chiffrement reversible des mots de passe ---

    Write-Verbose "[Find-AccountHygiene] Recherche des comptes avec chiffrement reversible..."
    try {
        $reversibleUsers = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true } `
            -Properties AllowReversiblePasswordEncryption, PasswordLastSet,
                        DistinguishedName, Description `
            -Server $Domain -ErrorAction Stop

        foreach ($user in $reversibleUsers) {
            $findings.Add([PSCustomObject]@{
                Category        = 'AccountHygiene'
                FindingID       = "HYG-$('{0:D3}' -f $findingIdCounter++)"
                FindingName     = 'Chiffrement reversible du mot de passe active'
                Object          = $user.SamAccountName
                ObjectDN        = $user.DistinguishedName
                ObjectType      = 'User'
                Risk            = 'Les mots de passe sont stockes avec un chiffrement reversible (equivalent d un stockage en clair). Un attaquant avec acces a la base NTDS peut recuperer les mots de passe en clair.'
                Severity        = 'Eleve'
                MitreRef        = 'T1003.003 (NTDS)'
                Description     = "[$($user.SamAccountName)] a AllowReversiblePasswordEncryption=True. Le mot de passe est stocke de maniere retrievable dans le fichier NTDS.dit. Une extraction de la base AD expose le mot de passe en clair."
                AttackPath      = "DCSync ou copie NTDS.dit → Dechiffrement avec cle SYSKEY → Mot de passe en clair de [$($user.SamAccountName)]"
                Recommendation  = "Desactiver immediatement : Set-ADUser '$($user.SamAccountName)' -AllowReversiblePasswordEncryption `$false, puis forcer un changement de mot de passe. Identifier pourquoi cette option etait activee (legacy CHAP ?)"
                PasswordLastSet = $user.PasswordLastSet
                CanRemediate    = $true
            })
        }
    }
    catch {
        Write-Warning "[Find-AccountHygiene] Erreur recherche chiffrement reversible : $_"
    }

    #endregion

    Write-Verbose "[Find-AccountHygiene] Total findings hygiene : $(@($Findings).Count)"
    return $findings
}
