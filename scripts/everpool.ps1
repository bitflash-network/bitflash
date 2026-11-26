# Everpool helper for Windows (docs/pool-registry.md): list the pools recorded
# on the chain, mine one, or create one, without typing RPC by hand.
# Double-click Everpool.cmd beside Bitflash.exe. Windows PowerShell 5.1.
#
# The wallet's interface has no Everpool screen yet. This helper starts the
# wallet (Bitflash.exe, the same program you open by hand) with its JSON-RPC
# on 127.0.0.1 and a random password kept in your Bitflash data folder, and
# talks to it. Nothing here leaves your computer, and nothing is sent without
# you typing YES.

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path $Here 'Bitflash.exe'
$DataDir = Join-Path $env:APPDATA 'Bitflash'
$Testnet = $args -contains '-testnet'
# Anything else given to Everpool.cmd (e.g. -nogui) is passed on to Bitflash.exe.
$Extra = @($args | Where-Object { $_ -ne '-testnet' })
if ($Testnet) { $RpcPort = 18432 } else { $RpcPort = 8432 }
$StateFile = Join-Path $DataDir 'everpool-helper.json'
$PassFile = Join-Path $DataDir 'everpool-rpc.txt'
$PoolZeroNote = 'the default pool everybody already mines (pool zero)'

function Get-State {
    if (Test-Path $StateFile) { return (Get-Content $StateFile -Raw | ConvertFrom-Json) }
    return [pscustomobject]@{ pool = '' }
}

function Save-State($s) {
    New-Item -ItemType Directory -Force $DataDir | Out-Null
    ($s | ConvertTo-Json) | Out-File -Encoding ascii $StateFile
}

function Get-Pass {
    if (-not (Test-Path $PassFile)) {
        New-Item -ItemType Directory -Force $DataDir | Out-Null
        $b = New-Object byte[] 24
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
        ([Convert]::ToBase64String($b) -replace '[+/=]', '') | Out-File -Encoding ascii -NoNewline $PassFile
    }
    return (Get-Content $PassFile -Raw).Trim()
}

function Invoke-Rpc($method, $params) {
    if ($null -eq $params) { $params = @() }
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('everpool:' + (Get-Pass)))
    $body = @{ jsonrpc = '1.0'; id = 1; method = $method; params = @($params) } | ConvertTo-Json -Depth 8 -Compress
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$RpcPort/" -Method Post -Body $body `
             -ContentType 'application/json' -Headers @{ Authorization = "Basic $auth" } -TimeoutSec 120
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw 'NOT_RUNNING' }
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $text = $reader.ReadToEnd()
        try { $r = $text | ConvertFrom-Json } catch { throw "the wallet answered: $text" }
    }
    if ($null -ne $r.error) {
        if ($r.error -is [string]) { throw $r.error }
        throw $r.error.message
    }
    return $r.result
}

function Test-Wallet {
    try { Invoke-Rpc 'getblockcount' | Out-Null; return $true } catch { return $false }
}

function Start-Wallet {
    if (Test-Wallet) { return $true }
    $mine = Get-Process -Name 'Bitflash' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe }
    if ($mine) {
        Write-Host ''
        Write-Host 'Bitflash is open, but not through this helper. Close it (File > Exit, and wait'
        Write-Host 'until it is gone), then choose this option again: the helper reopens it.'
        return $false
    }
    $st = Get-State
    $a = @('-rpcuser=everpool', "-rpcpassword=@$PassFile")
    if ($Testnet) { $a += '-testnet' }
    if ($st.pool -eq 'zero') { $a += '-p2pool' }
    elseif ($st.pool) { $a += "-p2pool=$($st.pool)" }
    $a += $Extra
    Start-Process -FilePath $Exe -ArgumentList $a -WorkingDirectory $Here | Out-Null
    Write-Host 'Opening Bitflash...'
    for ($i = 0; $i -lt 90; $i++) {
        Start-Sleep 2
        if (Test-Wallet) { Write-Host 'Bitflash is open and the helper can talk to it.'; return $true }
    }
    Write-Host 'Bitflash did not answer yet. If it shows a message, read it; then try again.'
    return $false
}

function Show-Pools {
    $l = Invoke-Rpc 'poollist'
    Write-Host ''
    Write-Host $l.note
    Write-Host ''
    $i = 0
    foreach ($p in $l.pools) {
        $i++
        if ($p.local) { continue }
        $fee = '{0:N2}%' -f ($p.feebps / 100.0)
        if ($i -eq 1) {
            Write-Host ("  {0,2}. {1}  [{2}]  {3}" -f $i, $p.name, $p.id.Substring(0, 8), $PoolZeroNote)
            continue
        }
        $status = $p.status
        if ($status -eq 'pending') { $status = "pending, $($p.confirmations) of 30 confirmations" }
        $alike = ''
        if ($p.samename -and @($p.samename).Count -gt 0) { $alike = '  (other pools have this name)' }
        Write-Host ("  {0,2}. {1}  [{2}]  fee {3}  {4}  blocks found lately: {5}{6}" -f `
            $i, $p.name, $p.fingerprint, $fee, $status, $p.claims, $alike)
    }
    Write-Host ''
    Write-Host 'The name is not unique: anyone can create a pool with any name. Check the'
    Write-Host 'fingerprint in brackets and the fee before you mine one.'
    return $l.pools
}

function Pick-Pool($pools) {
    $n = Read-Host 'Number of the pool (Enter to go back)'
    if (-not $n) { return $null }
    $k = 0
    if (-not [int]::TryParse($n, [ref]$k) -or $k -lt 1 -or $k -gt @($pools).Count) {
        Write-Host 'No pool with that number.'
        return $null
    }
    return @($pools)[$k - 1]
}

function Show-Pool($p) {
    if ($p.id) { $info = Invoke-Rpc 'poolinfo' @($p.id) } else { $info = $p }
    Write-Host ''
    Write-Host ($info | ConvertTo-Json -Depth 6)
}

function Mine-Pool($p, $isZero) {
    $st = Get-State
    if ($isZero) { $st.pool = 'zero' } else { $st.pool = $p.id }
    Save-State $st
    Write-Host ''
    if ($isZero) { Write-Host 'Chosen: P2Pool on the default pool (pool zero).' }
    else { Write-Host "Chosen: $($p.name) [$($p.fingerprint)], fee $('{0:N2}%' -f ($p.feebps / 100.0))." }
    Write-Host 'Bitflash has to be restarted for this. Close it (File > Exit), then choose'
    Write-Host '"Open Bitflash" in this menu. Then start the Bitflash Miner with:'
    Write-Host '    mine.cmd p2pool'
    Write-Host 'It mines through this computer''s own Bitflash, at 127.0.0.1:3333.'
}

function Create-Pool {
    Write-Host ''
    Write-Host 'Creating a pool burns 1 BTF and records it on the chain for good. It can never'
    Write-Host 'be edited or deleted: changing anything makes a different pool.'
    $name = Read-Host 'Name (letters, digits, spaces)'
    if (-not $name) { return }
    $fee = Read-Host 'Fee for you, the creator, in percent (0 to 3, Enter for 0)'
    $rec = @{ name = $name }
    if ($fee) {
        $f = 0.0
        if (-not [double]::TryParse($fee, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$f)) {
            Write-Host 'Not a number.'; return
        }
        $rec.feebps = [int][Math]::Round($f * 100)
        if ($rec.feebps -gt 0) {
            $addr = Read-Host 'Address that receives the fee (Enter for a new one of this wallet)'
            if (-not $addr) { $addr = Invoke-Rpc 'getnewaddress' }
            $rec.feeaddress = $addr
        }
    }
    $pv = Invoke-Rpc 'poolcreate' @('everpool', $rec)
    Write-Host ''
    Write-Host 'Review:'
    Write-Host "  Name:         $($pv.name)"
    Write-Host "  Fingerprint:  [$($pv.fingerprint)]   (what miners should check, not the name)"
    Write-Host "  Pool id:      $($pv.id)"
    Write-Host "  Fee:          $($pv.fee.percent)"
    if ($pv.fee.address) { Write-Host "  Fee goes to:  $($pv.fee.address)" }
    Write-Host "  Rules:        a share every $($pv.rules.spacing) s, paid over the last $($pv.rules.window) shares"
    Write-Host "  Cost:         $($pv.burn) BTF burned, gone for good"
    Write-Host '  Active:       after 30 confirmations, about an hour'
    if (@($pv.samename).Count -gt 0) { Write-Host '  Warning:      other pools already use this name' }
    if ($null -ne $pv.recorded) { Write-Host 'This exact pool is already recorded: nothing to create.'; return }
    Write-Host ''
    Write-Host 'If your wallet is encrypted, unlock it in Bitflash first.'
    $ok = Read-Host 'Type YES to burn 1 BTF and create this pool'
    if ($ok -cne 'YES') { Write-Host 'Nothing was sent.'; return }
    $r = Invoke-Rpc 'poolcreate' @('everpool', $rec, 'send')
    Write-Host ''
    Write-Host "Sent. Burn transaction: $($r.txid)"
    Write-Host "Pool id: $($r.id)  fingerprint [$($r.fingerprint)]"
    Write-Host 'It is active after 30 confirmations, about an hour. Then choose it with "Mine a pool".'
}

while ($true) {
    Write-Host ''
    Write-Host '=== Everpool ==='
    $st = Get-State
    if ($st.pool -eq 'zero') { Write-Host 'Mining choice: P2Pool, default pool' }
    elseif ($st.pool) { Write-Host "Mining choice: Everpool pool $($st.pool.Substring(0, 8))" }
    else { Write-Host 'Mining choice: none (Bitflash opens as usual)' }
    Write-Host '  1. Open Bitflash (with this helper)'
    Write-Host '  2. List pools'
    Write-Host '  3. Show a pool'
    Write-Host '  4. Mine a pool'
    Write-Host '  5. Create a pool'
    Write-Host '  6. Stop P2Pool mining (open Bitflash as usual next time)'
    Write-Host '  0. Quit'
    $c = Read-Host 'Choose'
    try {
        switch ($c) {
            '1' { Start-Wallet | Out-Null }
            '2' { if (Start-Wallet) { Show-Pools | Out-Null } }
            '3' { if (Start-Wallet) { $ps = Show-Pools; $p = Pick-Pool $ps; if ($p) { Show-Pool $p } } }
            '4' {
                if (Start-Wallet) {
                    $ps = Show-Pools; $p = Pick-Pool $ps
                    if ($p) { Mine-Pool $p ($p -eq @($ps)[0]) }
                }
            }
            '5' { if (Start-Wallet) { Create-Pool } }
            '6' { $st.pool = ''; Save-State $st; Write-Host 'Done. Restart Bitflash for it to apply.' }
            '0' { exit 0 }
            default { }
        }
    } catch {
        if ("$_" -eq 'NOT_RUNNING') { Write-Host 'Bitflash is not answering. Choose 1 to open it.' }
        else { Write-Host "Error: $_" }
    }
}
