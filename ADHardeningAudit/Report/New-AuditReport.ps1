function New-AuditReport {
    <#
    .SYNOPSIS
        Genere un rapport HTML style PingCastle et un CSV des findings AD.

    .DESCRIPTION
        Prend les PSCustomObjects produits par les 4 modules de detection et genere :
        - Un rapport HTML avec CSS inline, code couleur par severite, score global
        - Un CSV pour l'annexe technique du rapport ecrit
        Les deux fichiers sont horodates automatiquement.

    .PARAMETER Findings
        Tableau de PSCustomObjects produits par les fonctions Find-*.

    .PARAMETER Domain
        FQDN du domaine audite (pour l'en-tete du rapport).

    .PARAMETER OutputPath
        Dossier de sortie. Cree automatiquement s'il n'existe pas.

    .OUTPUTS
        Hashtable avec les cles HTML et CSV contenant les chemins des fichiers generes.

    .EXAMPLE
        $findings = Find-DangerousDelegation; New-AuditReport -Findings $findings -Domain mogador.local
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = '.\AuditResults'
    )

    # Creer le dossier de sortie
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $htmlPath    = Join-Path $OutputPath "AuditAD_${Domain}_${timestamp}.html"
    $csvPath     = Join-Path $OutputPath "AuditAD_${Domain}_${timestamp}.csv"
    $auditDate   = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'

    # Calcul des metriques globales
    $total    = $Findings.Count
    $critique = ($Findings | Where-Object Severity -eq 'Critique').Count
    $eleve    = ($Findings | Where-Object Severity -eq 'Eleve').Count
    $moyen    = ($Findings | Where-Object Severity -eq 'Moyen').Count
    $faible   = ($Findings | Where-Object Severity -eq 'Faible').Count

    # Score global style PingCastle (0 = parfait, 100 = critique)
    $score = [Math]::Min(100, ($critique * 25) + ($eleve * 10) + ($moyen * 3) + ($faible * 1))
    $scoreColor = if ($score -ge 75) { '#e74c3c' }
                  elseif ($score -ge 40) { '#e67e22' }
                  elseif ($score -ge 15) { '#f39c12' }
                  else { '#27ae60' }

    $scoreLabel = if ($score -ge 75) { 'CRITIQUE' }
                  elseif ($score -ge 40) { 'ELEVE' }
                  elseif ($score -ge 15) { 'MOYEN' }
                  else { 'FAIBLE' }

    #region --- CSS inline ---

    $css = @"
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    line-height: 1.6;
  }
  .header {
    background: linear-gradient(135deg, #161b22 0%, #1f2937 50%, #0d1117 100%);
    border-bottom: 3px solid #e74c3c;
    padding: 40px;
    text-align: center;
  }
  .header h1 {
    font-size: 2.2em;
    color: #f0f6fc;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .header .subtitle {
    color: #8b949e;
    font-size: 1em;
  }
  .header .domain-badge {
    display: inline-block;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 20px;
    padding: 4px 16px;
    margin-top: 12px;
    color: #58a6ff;
    font-weight: bold;
    font-size: 0.9em;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 30px; }

  /* Score global */
  .score-section {
    display: flex;
    gap: 20px;
    margin-bottom: 30px;
    flex-wrap: wrap;
  }
  .score-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 24px 32px;
    text-align: center;
    flex: 1;
    min-width: 140px;
  }
  .score-main {
    background: #161b22;
    border: 2px solid SCORE_COLOR;
    border-radius: 12px;
    padding: 24px 32px;
    text-align: center;
    flex: 2;
    min-width: 200px;
  }
  .score-number { font-size: 3em; font-weight: bold; }
  .score-label { font-size: 0.85em; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
  .sev-critique { color: #e74c3c; }
  .sev-eleve    { color: #e67e22; }
  .sev-moyen    { color: #f39c12; }
  .sev-faible   { color: #27ae60; }
  .sev-info     { color: #58a6ff; }

  /* Barre de progression score */
  .score-bar-wrap { margin: 8px 0; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; }
  .score-bar { height: 100%; background: SCORE_COLOR; border-radius: 4px; }

  /* Tables */
  .section-title {
    font-size: 1.3em;
    color: #f0f6fc;
    border-left: 4px solid #58a6ff;
    padding-left: 12px;
    margin: 30px 0 16px 0;
    font-weight: bold;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 30px;
    background: #161b22;
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid #30363d;
  }
  thead tr {
    background: #21262d;
    color: #8b949e;
    font-size: 0.8em;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  th, td {
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid #21262d;
    font-size: 0.88em;
  }
  tr:hover { background: #1c2128; }
  tr:last-child td { border-bottom: none; }
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.78em;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .badge-critique { background: #3d0000; color: #ff6b6b; border: 1px solid #c0392b; }
  .badge-eleve    { background: #3d1a00; color: #ff9f43; border: 1px solid #e67e22; }
  .badge-moyen    { background: #3d2e00; color: #ffd32a; border: 1px solid #f39c12; }
  .badge-faible   { background: #003d10; color: #2ecc71; border: 1px solid #27ae60; }
  .badge-acl      { background: #1a0040; color: #a855f7; border: 1px solid #7c3aed; }

  /* Expand details */
  details { margin: -6px 0 6px 0; }
  summary { cursor: pointer; color: #58a6ff; font-size: 0.82em; padding: 2px 0; }
  summary:hover { color: #79c0ff; }
  .detail-box {
    background: #0d1117;
    border-left: 3px solid #30363d;
    border-radius: 0 6px 6px 0;
    padding: 10px 14px;
    margin-top: 6px;
    font-size: 0.82em;
    color: #8b949e;
  }
  .attack-path {
    background: #1a0a0a;
    border-left: 3px solid #e74c3c;
    padding: 8px 12px;
    border-radius: 0 4px 4px 0;
    margin-top: 6px;
    font-family: 'Courier New', monospace;
    font-size: 0.8em;
    color: #ff6b6b;
  }
  .mitre-badge {
    display: inline-block;
    background: #161b22;
    border: 1px solid #388bfd;
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 0.75em;
    color: #58a6ff;
    font-family: monospace;
  }
  .reco-box {
    background: #0a1a0a;
    border-left: 3px solid #27ae60;
    padding: 8px 12px;
    border-radius: 0 4px 4px 0;
    margin-top: 6px;
    font-size: 0.82em;
    color: #2ecc71;
  }

  /* Validation tableau */
  .val-ok { color: #27ae60; font-weight: bold; }
  .val-warn { color: #f39c12; }
  .val-no { color: #e74c3c; }

  /* Footer */
  .footer {
    text-align: center;
    color: #484f58;
    font-size: 0.8em;
    padding: 30px;
    border-top: 1px solid #21262d;
    margin-top: 40px;
  }
  .explain-banner {
    background: #160a2e;
    border: 1px solid #7c3aed;
    border-radius: 8px;
    padding: 12px 18px;
    margin-bottom: 16px;
    font-size: 0.88em;
    color: #c084fc;
  }
  code {
    background: #21262d;
    border-radius: 4px;
    padding: 1px 5px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
    color: #79c0ff;
  }
</style>
"@

    # Remplacer SCORE_COLOR dans le CSS
    $css = $css -replace 'SCORE_COLOR', $scoreColor

    #endregion

    #region --- Helper : generer une ligne de tableau ---

    function ConvertTo-HtmlRow {
        param([PSCustomObject]$Finding)

        $sev      = $Finding.Severity
        $cat      = $Finding.Category
        $badgeCss = switch ($sev) {
            'Critique' { 'badge-critique' }
            'Eleve'    { 'badge-eleve' }
            'Moyen'    { 'badge-moyen' }
            'Faible'   { 'badge-faible' }
            default    { 'badge-faible' }
        }
        if ($cat -eq 'ACLAbuse') { $badgeCss = 'badge-acl' }

        $mitre = if ($Finding.MitreRef) { "<span class='mitre-badge'>$($Finding.MitreRef)</span>" } else { '' }

        $detailHtml = @"
<details>
  <summary>Details &amp; chemin d'attaque</summary>
  <div class='detail-box'>
    <strong>Description :</strong><br/>$([System.Web.HttpUtility]::HtmlEncode($Finding.Description))<br/><br/>
    <div class='attack-path'>⚔ ATTACK PATH : $([System.Web.HttpUtility]::HtmlEncode($Finding.AttackPath))</div>
    <div class='reco-box'>✅ REMEDIATION : $([System.Web.HttpUtility]::HtmlEncode($Finding.Recommendation))</div>
  </div>
</details>
"@

        return @"
<tr>
  <td><code>$($Finding.FindingID)</code></td>
  <td><span class='badge $badgeCss'>$sev</span></td>
  <td>$($Finding.FindingName)</td>
  <td><code>$($Finding.Object)</code></td>
  <td>$($Finding.ObjectType)</td>
  <td>$mitre</td>
  <td>$detailHtml</td>
</tr>
"@
    }

    #endregion

    #region --- Construire le corps HTML par categorie ---

    $categoriesConfig = @(
        @{ Key = 'Delegation';     Title = '🔑 Delegation Kerberos'; Color = '#e74c3c' }
        @{ Key = 'AccountHygiene'; Title = '🧹 Hygiene des comptes';  Color = '#e67e22' }
        @{ Key = 'EscalationPath'; Title = '⬆ Chemins d escalade';   Color = '#f39c12' }
        @{ Key = 'ACLAbuse';       Title = '🛡 Abus d ACL (Explain Only)'; Color = '#a855f7' }
    )

    $tableHeaders = @"
<tr>
  <th>ID</th>
  <th>Severite</th>
  <th>Finding</th>
  <th>Objet</th>
  <th>Type</th>
  <th>MITRE</th>
  <th>Details</th>
</tr>
"@

    $bodySections = ''

    foreach ($catConf in $categoriesConfig) {
        $catFindings = $Findings | Where-Object Category -eq $catConf.Key
        $count       = if ($catFindings) { @($catFindings).Count } else { 0 }

        $aclBanner = if ($catConf.Key -eq 'ACLAbuse') {
            "<div class='explain-banner'>⚠️ <strong>EXPLAIN ONLY</strong> — Ce module ne propose pas de remediation automatique. Chaque ACE doit etre validee manuellement par un humain pour distinguer delegation legitime et backdoor.</div>"
        } else { '' }

        $rows = ''
        if ($count -gt 0) {
            foreach ($f in $catFindings) {
                $rows += ConvertTo-HtmlRow -Finding $f
            }
        }
        else {
            $rows = "<tr><td colspan='7' style='text-align:center;color:#27ae60;padding:20px'>✅ Aucun finding detecte dans cette categorie</td></tr>"
        }

        $bodySections += @"
<div class='section-title' style='border-color:$($catConf.Color)'>$($catConf.Title) <span style='color:#8b949e;font-size:0.8em;font-weight:normal'>— $count finding(s)</span></div>
$aclBanner
<table>
  <thead>$tableHeaders</thead>
  <tbody>$rows</tbody>
</table>
"@
    }

    #endregion

    #region --- Tableau de validation (findings connus) ---

    $validationTable = @"
<div class='section-title' style='border-color:#58a6ff'>📋 Tableau de Validation — Comparaison avec BloodHound / PingCastle</div>
<table>
  <thead>
    <tr>
      <th>Finding connu</th>
      <th>Detecte par cet outil</th>
      <th>Detecte par BloodHound/PingCastle</th>
      <th>Module</th>
      <th>Confiance</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>svc-plurihotel Kerberoastable</td>
      <td class='val-ok'>$(if (($Findings | Where-Object { $_.Object -like '*plurihotel*' -and $_.FindingName -like '*Kerberoast*' }).Count -gt 0) { '✅ Detecte' } else { '<span class="val-warn">⚠️ Non trouve (verifier SPN)</span>' })</td>
      <td class='val-ok'>✅</td>
      <td><code>Find-AccountHygiene</code></td>
      <td>Haute</td>
    </tr>
    <tr>
      <td>svc-plurihotel Unconstrained Delegation</td>
      <td class='val-ok'>$(if (($Findings | Where-Object { $_.Object -like '*plurihotel*' -and $_.Category -eq 'Delegation' }).Count -gt 0) { '✅ Detecte' } else { '<span class="val-warn">⚠️ Non trouve (verifier TrustedForDelegation)</span>' })</td>
      <td class='val-ok'>✅</td>
      <td><code>Find-Delegation</code></td>
      <td>Haute</td>
    </tr>
    <tr>
      <td>Nesting IT-Support → Domain Admins</td>
      <td class='val-ok'>$(if (($Findings | Where-Object { $_.FindingName -like '*IT-Support*' }).Count -gt 0) { '✅ Detecte' } else { '<span class="val-warn">⚠️ Non trouve (verifier nesting)</span>' })</td>
      <td class='val-ok'>✅</td>
      <td><code>Find-EscalationPath</code></td>
      <td>Haute</td>
    </tr>
    <tr>
      <td>Delegation liee a LAPS mal configuree</td>
      <td class='val-ok'>$(if (($Findings | Where-Object { $_.FindingName -like '*LAPS*' }).Count -gt 0) { '✅ Detecte' } else { '<span class="val-warn">⚠️ Partiel (LAPS correctement configure)</span>' })</td>
      <td class='val-warn'>⚠️ Partiel</td>
      <td><code>Find-Delegation</code></td>
      <td>Moyenne</td>
    </tr>
    <tr>
      <td>Comptes AdminCount=1 orphelins</td>
      <td class='val-ok'>$(if (($Findings | Where-Object { $_.FindingName -like '*AdminCount*' }).Count -gt 0) { '✅ Detecte' } else { '✅ Aucun orphelin (bon signe)' })</td>
      <td class='val-warn'>⚠️ Non disponible</td>
      <td><code>Find-EscalationPath</code></td>
      <td>Haute</td>
    </tr>
    <tr>
      <td>Comptes AS-REP Roastable</td>
      <td class='val-ok'>$(if (($Findings | Where-Object { $_.FindingName -like '*AS-REP*' }).Count -gt 0) { "✅ $( ($Findings | Where-Object { $_.FindingName -like '*AS-REP*' }).Count ) compte(s)" } else { '✅ Aucun (bon signe)' })</td>
      <td class='val-ok'>✅</td>
      <td><code>Find-AccountHygiene</code></td>
      <td>Haute</td>
    </tr>
  </tbody>
</table>
"@

    #endregion

    #region --- Assembler le HTML complet ---

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Audit AD - $Domain - $auditDate</title>
  <meta name="description" content="Rapport d audit de securite Active Directory pour le domaine $Domain genere par ADHardeningAudit v1.0">
  $css
</head>
<body>

<!-- EN-TETE -->
<div class='header'>
  <h1>🔒 AD Hardening Audit Report</h1>
  <div class='subtitle'>Rapport d audit de securite Active Directory</div>
  <div class='domain-badge'>🌐 $Domain</div>
  <div class='subtitle' style='margin-top:8px'>Genere le $auditDate | ADHardeningAudit v1.0</div>
</div>

<div class='container'>

<!-- SCORE ET METRIQUES -->
<div class='score-section'>
  <div class='score-main'>
    <div class='score-number' style='color:$scoreColor'>$score / 100</div>
    <div class='score-label'>Score de risque global</div>
    <div class='score-bar-wrap'><div class='score-bar' style='width:$score%'></div></div>
    <div style='margin-top:8px;font-size:0.9em;color:$scoreColor;font-weight:bold'>$scoreLabel</div>
  </div>
  <div class='score-card'>
    <div class='score-number sev-critique'>$critique</div>
    <div class='score-label'>Critique</div>
  </div>
  <div class='score-card'>
    <div class='score-number sev-eleve'>$eleve</div>
    <div class='score-label'>Eleve</div>
  </div>
  <div class='score-card'>
    <div class='score-number sev-moyen'>$moyen</div>
    <div class='score-label'>Moyen</div>
  </div>
  <div class='score-card'>
    <div class='score-number sev-faible'>$faible</div>
    <div class='score-label'>Faible</div>
  </div>
  <div class='score-card'>
    <div class='score-number' style='color:#58a6ff'>$total</div>
    <div class='score-label'>Total</div>
  </div>
</div>

<!-- FINDINGS PAR CATEGORIE -->
$bodySections

<!-- TABLEAU DE VALIDATION -->
$validationTable

<!-- JUSTIFICATION ACL EXPLAIN-ONLY -->
<div class='section-title' style='border-color:#a855f7'>📖 Justification : Pourquoi ACL = Explain Only</div>
<div style='background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:30px;'>
<p style='margin-bottom:12px'>Une ACE <code>GenericAll</code> ou <code>WriteDacl</code> sur un objet peut etre :</p>
<ul style='margin-left:20px;line-height:2'>
  <li>Une <strong style='color:#e74c3c'>porte derobee</strong> laissee par un attaquant ou une mauvaise configuration historique</li>
  <li>Une <strong style='color:#27ae60'>delegation legitime</strong> (ex : le groupe Helpdesk a <code>WriteProperty</code> sur les mots de passe pour du reset utilisateur — normal dans un tenant hotelier avec support IT externalise)</li>
</ul>
<p style='margin-top:12px;color:#8b949e'>Un script ne peut pas distinguer les deux sans comprendre l intention metier. Retirer automatiquement une ACE "suspecte" risque de casser une delegation legitime en production. C est pourquoi ce module <strong style='color:#a855f7'>detecte et explique uniquement</strong>, en affichant le chemin d attaque, et laisse la decision a un humain.</p>
<p style='margin-top:12px;color:#8b949e'><strong>Reference MITRE :</strong> <span class='mitre-badge'>T1222</span> <span class='mitre-badge'>T1078</span> <span class='mitre-badge'>T1484.001</span></p>
</div>

</div><!-- /container -->

<div class='footer'>
  ADHardeningAudit v1.0 | Domaine : $Domain | $auditDate<br/>
  Ce rapport est confidentiel et destine uniquement aux equipes securite autorisees.
</div>

</body>
</html>
"@

    #endregion

    # Ecrire les fichiers
    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)
    Write-Verbose "[New-AuditReport] HTML genere : $htmlPath"

    # CSV
    $Findings | Select-Object FindingID, Category, Severity, FindingName, Object, ObjectType, MitreRef, Recommendation |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Verbose "[New-AuditReport] CSV genere : $csvPath"

    # Ouvrir automatiquement le rapport HTML
    try {
        Start-Process $htmlPath -ErrorAction SilentlyContinue
    }
    catch {}

    return @{
        HTML  = $htmlPath
        CSV   = $csvPath
        Score = $score
    }
}
