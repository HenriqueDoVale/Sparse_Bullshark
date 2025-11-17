param (
    [int]$transaction_size,
    [int]$n_transactions,
    [string]$mode = "sparse" # New parameter with default value
)

# Define the path to the CSV file
$csvPath = "./shared/nodes.csv"

# Check if the file exists
if (-not (Test-Path $csvPath)) {
    Write-Host "nodes.csv not found in shared/. Please generate it first."
    exit 1
}

# Validate required numeric parameters
if (-not $transaction_size -or -not $n_transactions) {
    Write-Host "Error: Both -transaction_size and -n_transactions parameters are required."
    Write-Host "Usage: .\run_sparse.ps1 -transaction_size <int> -n_transactions <int> [-mode <sparse|dense>]"
    exit 1
}

# Skip the header and read all lines
$lines = Get-Content $csvPath | Select-Object -Skip 1

Write-Host "--------------------------------------------------"
Write-Host " 🚀 STARTING EXPERIMENT"
Write-Host " -------------------------------------------------"
Write-Host "   Protocol:  $mode"
Write-Host "   Tx Size:   $transaction_size bytes"
Write-Host "   Tx Count:  $n_transactions per block"
Write-Host "--------------------------------------------------"

foreach ($line in $lines) {
    $parts = $line -split ","
    $id = $parts[0].Trim()
    $hostname = $parts[1].Trim()
    $port = $parts[2].Trim()

    Write-Host "Starting node ${id} on ${hostname}:${port}..."

    $allArgs = "$id $transaction_size $n_transactions"
    
    # We construct a command that sets the env var *inside* the new shell, then runs cargo.
    # Note the backtick ` before $env:PROTOCOL to prevent the current shell from expanding it.
    $commandString = "`$env:PROTOCOL='$mode'; cargo run --release --package sparse_bullshark --bin sparse_bullshark $allArgs"

    if ($IsLinux) {
        # Use 'pwsh' on Linux
        Start-Process "pwsh" -ArgumentList "-NoExit", "-Command", $commandString
    }
    else {
        # Use 'powershell.exe' on Windows
        Start-Process "powershell.exe" -ArgumentList "-NoExit", "-Command", $commandString
    }
}

Write-Host "All nodes started."