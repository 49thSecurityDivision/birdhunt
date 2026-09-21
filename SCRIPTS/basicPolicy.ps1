#####################################################################
# Disable print spooler
#####################################################################
try {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue 
    Set-Service -Name Spooler -StartupType Disabled
    Write-Host "Print spooler has been disabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable print spooler."
}

#####################################################################
# Disable guest account
#####################################################################
try {
    $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
    Disable-ADAccount -Identity $guestAccount.SamAccountName
    Write-Host "Guest account has been disabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable Guest account."
}

#####################################################################
# Push policy updates to entire forest
#####################################################################
try {
    Get-ADComputer -Filter * | ForEach-Object { Invoke-GPUpdate -Computer $_.Name -Force -RandomDelayInMinutes 0 }
    Write-Host "Policy updates pushed to forest." -ForegroundColor Green
}
catch {
    Write-Error "Policy updates failed to push."
}

Read-Host -Prompt "Press Enter to exit."