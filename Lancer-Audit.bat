@echo off
title ADHardeningAudit v1.0 - Audit Active Directory
color 0B

:: ─── Detection automatique du domaine ────────────────────────────────────────
:: %USERDNSDOMAIN% est defini par Windows des que la machine est jointe a un domaine AD
:: %USERDOMAIN%    est le nom NetBIOS (ex: MOGADOR) - moins precis
:: On prefere USERDNSDOMAIN (ex: mogador.local) pour les cmdlets AD

set "DOMAIN_AUTO=%USERDNSDOMAIN%"

:: Fallback : si USERDNSDOMAIN est vide (machine hors domaine), essayer via PowerShell
if "%DOMAIN_AUTO%"=="" (
    for /f "delims=" %%i in ('PowerShell.exe -NoProfile -Command "(Get-WmiObject Win32_ComputerSystem).Domain" 2^>nul') do set "DOMAIN_AUTO=%%i"
)

:: Dernier fallback : demander a l'utilisateur
if "%DOMAIN_AUTO%"=="" (
    echo  [AVERTISSEMENT] Aucun domaine detecte automatiquement.
    echo  Cette machine n'est peut-etre pas jointe a un domaine Active Directory.
    echo.
    set /p DOMAIN_AUTO="  Entrez le FQDN du domaine manuellement (ex: mogador.local) : "
)

echo.
echo  ==================================================================
echo   ADHardeningAudit v1.0 ^| Audit et Remediation Active Directory
echo  ==================================================================
echo.
echo   Domaine detecte  : %DOMAIN_AUTO%
echo   Machine          : %COMPUTERNAME%
echo   Utilisateur      : %USERDOMAIN%\%USERNAME%
echo.
echo  ==================================================================
echo.

:: Verifier que PowerShell est disponible
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERREUR] PowerShell introuvable sur cette machine.
    pause
    exit /b 1
)

:: Demander elevation UAC si pas admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [INFO] Elevation des privileges necessaire...
    PowerShell.exe -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo  [OK] Privileges administrateur confirmes
echo  [OK] Domaine cible : %DOMAIN_AUTO%
echo.

:: ─── Menu de lancement ────────────────────────────────────────────────────────
echo  Choisissez le mode de lancement :
echo.
echo  [1] Audit complet (rapport HTML genere automatiquement)
echo  [2] Audit + Demo remediations -WhatIf (aucune modification)
echo  [3] Audit verbeux (mode debug)
echo  [4] Changer de domaine manuellement
echo  [5] Quitter
echo.
set /p choix="  Votre choix (1/2/3/4/5) : "

if "%choix%"=="1" goto AUDIT_COMPLET
if "%choix%"=="2" goto AUDIT_REMEDIATE
if "%choix%"=="3" goto AUDIT_VERBOSE
if "%choix%"=="4" goto CHANGER_DOMAINE
if "%choix%"=="5" goto FIN
goto AUDIT_COMPLET

:CHANGER_DOMAINE
echo.
set /p DOMAIN_AUTO="  Nouveau domaine FQDN (ex: mogador.local) : "
echo  [OK] Domaine mis a jour : %DOMAIN_AUTO%
echo.
goto AUDIT_COMPLET

:AUDIT_COMPLET
echo.
echo  [LANCEMENT] Audit complet sur [%DOMAIN_AUTO%]...
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "& '%~dp0ADHardeningAudit\Run-FullAudit.ps1' -Domain '%DOMAIN_AUTO%'"
goto FIN_AUDIT

:AUDIT_REMEDIATE
echo.
echo  [LANCEMENT] Audit + Demo remediation WhatIf sur [%DOMAIN_AUTO%]...
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "& '%~dp0ADHardeningAudit\Run-FullAudit.ps1' -Domain '%DOMAIN_AUTO%' -RemediateDemo"
goto FIN_AUDIT

:AUDIT_VERBOSE
echo.
echo  [LANCEMENT] Audit verbeux sur [%DOMAIN_AUTO%]...
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "& '%~dp0ADHardeningAudit\Run-FullAudit.ps1' -Domain '%DOMAIN_AUTO%' -Verbose"
goto FIN_AUDIT

:FIN_AUDIT
echo.
echo  ==================================================================
echo   Audit termine. Le rapport HTML a ete ouvert dans le navigateur.
echo   Fichiers disponibles dans : %~dp0ADHardeningAudit\AuditResults\
echo  ==================================================================
echo.
pause
goto :EOF

:FIN
echo.
echo  Au revoir.
exit /b 0
