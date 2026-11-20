param([ValidateSet('postgres','sqlite')][string]$Database = 'postgres')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path '.venv/Scripts/python.exe')) { python -m venv .venv }
& '.venv/Scripts/python.exe' -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Installation des dépendances impossible.' }
& '.venv/Scripts/python.exe' -m devsec.setup
& '.venv/Scripts/python.exe' -m devsec.run --database $Database
