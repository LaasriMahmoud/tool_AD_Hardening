@{
    # Module identity
    RootModule        = 'ADHardeningAudit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f9c2d1-4b7e-4f8a-9c2b-1d3e5f7a9b0c'
    Author            = 'ADHardeningAudit'
    CompanyName       = 'PFA - mogador.local'
    Copyright         = '(c) 2026. Tous droits reserves.'
    Description       = 'Module PowerShell d audit et de remediation Active Directory. Detecte les delegations dangereuses, les problemes d hygiene des comptes, les chemins d escalade de privileges et les abus d ACL.'

    # PowerShell version minimale
    PowerShellVersion = '5.1'

    # Modules requis
    RequiredModules   = @('ActiveDirectory')

    # Fonctions exportees
    FunctionsToExport = @(
        # Detection
        'Find-DangerousDelegation',
        'Find-AccountHygieneIssues',
        'Find-PrivilegeEscalationPaths',
        'Find-ACLAbuses',

        # Remediation
        'Repair-DangerousDelegation',
        'Repair-AccountHygieneIssues',
        'Repair-EscalationPaths',

        # Rapport
        'New-AuditReport',

        # Orchestration
        'Invoke-ADHardeningAudit'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # Metadata affichee dans la galerie
    PrivateData = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'Hardening', 'Pentest')
            ReleaseNotes = 'Version initiale - Audit AD mogador.local'
        }
    }
}
