# Run as Administrator

# Output file path
$OutputFile = "C:\Temp\UserPasswords.txt"

# Create the directory if it doesn't exist
if (!(Test-Path -Path (Split-Path $OutputFile))) {
    New-Item -ItemType Directory -Path (Split-Path $OutputFile) | Out-Null
}

# Clear existing file or create new
"" | Out-File -FilePath $OutputFile

# Function to generate a random complex password (min 15 characters)
function New-RandomPassword {
    param (
        [int]$length = 15
    )

    $lower = 'abcdefghijklmnopqrstuvwxyz'
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $digits = '0123456789'
    $symbols = '!@#$%^&*()-_=+[]{}'
    $all = $lower + $upper + $digits + $symbols

    # Ensure at least one of each category
    $password = (
        ($lower | Get-Random -Count 1) +
        ($upper | Get-Random -Count 1) +
        ($digits | Get-Random -Count 1) +
        ($symbols | Get-Random -Count 1)
    )

    # Fill the rest randomly
    $remaining = $length - 4
    $password += -join ((1..$remaining) | ForEach-Object { $all | Get-Random })

    # Shuffle the final result
    -join ($password.ToCharArray() | Sort-Object { Get-Random })
}

# Get all local users (excluding Administrator and Guest)
$users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }

foreach ($user in $users) {
    try {
        $newPasswordPlain = New-RandomPassword
        $securePassword = ConvertTo-SecureString $newPasswordPlain -AsPlainText -Force

        Set-LocalUser -Name $user.Name -Password $securePassword

        # Log username and password
        "$($user.Name): $newPasswordPlain" | Out-File -FilePath $OutputFile -Append

        Write-Host "Password changed for: $($user.Name)" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed for: $($user.Name). Error: $_" -ForegroundColor Red
    }
}