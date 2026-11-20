$ErrorActionPreference = 'Stop'
$prototypeRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$statePath = Join-Path $prototypeRoot '.local/processes.json'
if (-not (Test-Path -LiteralPath $statePath)) { Write-Host 'Aucun lancement enregistré.'; exit }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$expectedPython = [IO.Path]::GetFullPath((Join-Path $prototypeRoot '.venv/Scripts/python.exe'))
foreach ($ownedId in (@($state.supervisor) + @($state.children))) {
    $ownedProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $ownedId" -ErrorAction SilentlyContinue
    if ($null -ne $ownedProcess -and $ownedProcess.ExecutablePath -eq $expectedPython -and $ownedProcess.CommandLine -match 'devsec\.(run|api|demo|collector|rules)') {
        Stop-Process -Id $ownedId
    }
}
Write-Host 'Processus du prototype arrêtés. Les données sont conservées.'
