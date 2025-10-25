param (
    [int]$transaction_size,
    [int]$n_transactions
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
    Write-Host "Usage: .\run_sparse.ps1 -transaction_size <int> -n_transactions <int>"
    exit 1
}

# Skip the header and read all lines
$lines = Get-Content $csvPath | Select-Object -Skip 1

foreach ($line in $lines) {
    $parts = $line -split ","
    $id = $parts[0].Trim()
    $hostname = $parts[1].Trim()
    $port = $parts[2].Trim()

    Write-Host "Starting node ${id} on ${hostname}:${port}..."

    $allArgs = "$id $transaction_size $n_transactions"
    
    # Assuming your package and binary are named 'sparse-bullshark' based on your project structure
    Start-Process "powershell.exe" -ArgumentList "-NoExit", "-Command", "cargo run --release --package sparse_bullshark --bin sparse_bullshark $allArgs"
}

Write-Host "All nodes started."