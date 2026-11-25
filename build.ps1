<#
.SYNOPSIS
  Build the Anubis Automation Script Signer on a Windows host with Docker Desktop.

.DESCRIPTION
  The PowerShell twin of build.sh for Windows hosts: it builds the
  same container images (build/docker/*.Dockerfile, Linux containers)
  and runs the same in-container scripts (build/scripts/*.sh) with
  the same named volumes, so a Windows machine produces the same files:

    .\build.ps1 <all|linux|windows|android|cli-linux|cli-windows|all-linux-host|test|images|clean> [-Out DIR] [-Release] [-KeepCache] [-NoEmulator]

  all builds linux, windows and android (the same as all-linux-host on Windows);
  macos and ios need a Mac with Xcode (see the README). The Android release
  keystore defaults to $HOME\.awake-helix-signing\android-release.jks
  (generated on first use; back it up). Override with the environment
  variables HELIX_ANDROID_KEYSTORE, HELIX_ANDROID_KEYSTORE_PASSWORD_FILE and
  HELIX_ANDROID_KEY_ALIAS (default: the keystore's only key), as for
  build.sh. The Android emulator smoke test
  needs /dev/kvm and does not run under Docker Desktop.

  Every build ends (also when it fails) by removing what it created: this
  script's Docker images and volumes, its BuildKit builder with its build
  cache, and the generated files in app\. dist\ (the
  results) and the Android signing key are kept. -KeepCache (or
  HELIX_KEEP_CACHE=1) keeps the caches for a faster next build;
  "clean" removes them later.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet('all', 'linux', 'windows', 'android', 'cli-linux', 'cli-windows', 'all-linux-host', 'test', 'images', 'clean', 'macos', 'ios')]
  [string]$Platform,
  [string]$Out = '',
  [switch]$Release,
  [switch]$KeepCache,
  [switch]$NoEmulator
)
$ErrorActionPreference = 'Stop'
$Rs = $PSScriptRoot
$Prefix = 'anubisauto-signer'
$MinFreeGb = if ($env:HELIX_MIN_FREE_GB) { [int]$env:HELIX_MIN_FREE_GB } else { 10 }
$Builder = $Prefix
if ($env:HELIX_KEEP_CACHE -eq '1') { $KeepCache = $true }

function Say([string]$Text) { Write-Host "==> $Text" }
function Fail([string]$Text) { Write-Error "build.ps1: $Text"; exit 1 }

if ($Platform -in @('macos', 'ios')) {
  Write-Host "build.ps1: '$Platform' cannot be built on Windows: Apple's toolchains (Xcode, codesign) run only on macOS. Run ./build.sh $Platform on a Mac."
  exit 3
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail 'Docker Desktop is required (https://www.docker.com/products/docker-desktop/), with Linux containers.' }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail 'Docker Desktop is not running: start it and wait until it says "Engine running".' }
$osType = docker info --format '{{.OSType}}'
if ($osType -ne 'linux') { Fail 'Docker Desktop must use Linux containers (right-click the tray icon > Switch to Linux containers).' }

# Shell scripts must keep LF endings (.gitattributes) or sh fails in the container.
if ((Get-Content -Raw (Join-Path $Rs 'build\scripts\common.sh')) -match "`r`n") {
  Fail 'build/scripts/*.sh have Windows line endings: run  git config core.autocrlf false  and check the repository out again.'
}

$versions = @{}
foreach ($line in Get-Content (Join-Path $Rs 'build\versions.env')) {
  if ($line -match "^([A-Z0-9_]+)='?([^']*)'?$") { $versions[$Matches[1]] = $Matches[2] }
}
$toolchain = (Select-String -Path (Join-Path $Rs 'rust-toolchain.toml') -Pattern '^channel\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value

function Need-Disk([int]$Gb) {
  $drive = (Get-Item $Rs).PSDrive
  $free = [math]::Floor($drive.Free / 1GB)
  if ($free -lt ($Gb + $MinFreeGb)) { Fail "only $free GB free on $($drive.Name):; this step needs about $Gb GB and $MinFreeGb GB must stay free." }
  Say "disk: $free GB free (step needs ~$Gb GB)"
}

# Images are built by a BuildKit builder of their own, so their build cache can
# be removed with the builder without touching other build caches.
function Ensure-Builder {
  docker buildx inspect $Builder *> $null
  if ($LASTEXITCODE -eq 0) { return }
  docker buildx version *> $null
  if ($LASTEXITCODE -ne 0) { Fail 'Docker Buildx is required (it is part of Docker Desktop).' }
  Say "creating the BuildKit builder $Builder ($($versions['BUILDKIT_IMAGE']))"
  docker buildx create --name $Builder --driver docker-container --driver-opt "image=$($versions['BUILDKIT_IMAGE'])" | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "could not create the BuildKit builder $Builder" }
}

function Free-Gb { [math]::Floor((Get-Item $Rs).PSDrive.Free / 1GB) }

# Remove what the build created; dist\ and the Android signing key stay.
function Invoke-Cleanup {
  if ($KeepCache) { Say 'kept the build caches (-KeepCache); .\build.ps1 clean removes them'; return }
  $before = Free-Gb
  Say 'cleaning up what the build created (kept: dist\ and the Android signing key; -KeepCache skips this)'
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    docker ps -aq --filter "label=$Prefix.build" 2> $null | ForEach-Object { docker rm -f $_ *> $null }
    $app = Join-Path $Rs 'app'
    foreach ($rel in 'dist', 'src-tauri\gen', 'src-tauri\binaries', 'src-tauri\icons', 'src-tauri\app-icon.png') {
      $path = Join-Path $app $rel
      if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue }
      if (Test-Path -LiteralPath $path) { Say "could not remove $path (remove it by hand)" }
    }
    # The node_modules volume's mount point (an empty directory) after container builds.
    $modules = Join-Path $app 'node_modules'
    if ((Test-Path -LiteralPath $modules) -and -not (Get-ChildItem -LiteralPath $modules -Force | Select-Object -First 1)) { Remove-Item -LiteralPath $modules -Force }
    docker images --format '{{.Repository}}:{{.Tag}}' 2> $null | Where-Object { $_ -like "$Prefix-build-*" } | ForEach-Object { docker rmi -f $_ *> $null }
    docker volume ls -q --filter "name=^$Prefix-" 2> $null | ForEach-Object { docker volume rm -f $_ *> $null }
    # Removing the builder also removes its build cache (its state volume).
    docker buildx rm --force $Builder *> $null
    # Also when buildx lost track of it: the builder's container and state volume by name.
    docker rm -f "buildx_buildkit_${Builder}0" *> $null
    docker volume rm -f "buildx_buildkit_${Builder}0_state" *> $null
    $buildkit = $versions['BUILDKIT_IMAGE']
    if (-not (docker ps -aq --filter "ancestor=$buildkit" 2> $null)) { docker rmi $buildkit *> $null }
  } finally {
    $ErrorActionPreference = $old
  }
  Say "cleanup done: $(Free-Gb) GB free (was $before GB)"
}

function Image-For([string]$Kind) {
  $dockerfile = Join-Path $Rs "build\docker\$Kind.Dockerfile"
  $text = "$toolchain linux/amd64" + (Get-Content -Raw $dockerfile) + (Get-Content -Raw (Join-Path $Rs 'build\docker\install-node-rust.sh')) + (Get-Content -Raw (Join-Path $Rs 'build\versions.env'))
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text.Replace("`r`n", "`n"))
  $hash = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)[0..5] | ForEach-Object { $_.ToString('x2') })
  $image = "$Prefix-build-${Kind}:$hash"
  docker image inspect $image *> $null
  if ($LASTEXITCODE -ne 0) {
    Need-Disk ($(if ($Kind -eq 'android') { 8 } else { 4 }))
    Say "building image $image (once; cached afterwards)"
    Ensure-Builder
    $buildArgs = @('buildx', 'build', '--builder', $Builder, '--load', '--platform', 'linux/amd64', '-t', $image, '-f', $dockerfile, '--build-arg', "RUST_TOOLCHAIN=$toolchain")
    foreach ($key in $versions.Keys) {
      if ($key -ne 'BUILDKIT_IMAGE') { $buildArgs += @('--build-arg', "$key=$($versions[$key])") }
    }
    $buildArgs += (Join-Path $Rs 'build\docker')
    & docker @buildArgs
    if ($LASTEXITCODE -ne 0) { Fail "docker build of $image failed" }
  }
  return $image
}

function Run-In([string]$Kind, [string[]]$Extra, [string]$Script, [string[]]$ScriptArgs) {
  $image = Image-For $Kind
  $runArgs = @('run', '--rm', '--init', '--platform', 'linux/amd64', '--label', "$Prefix.build=$Kind",
    '-v', "${Rs}:/src",
    '-v', "${Prefix}-cargo-registry:/usr/local/cargo/registry",
    '-v', "${Prefix}-cargo-git:/usr/local/cargo/git",
    '-v', "${Prefix}-target-${Kind}:/cache/target",
    '-v', "${Prefix}-node-modules-${Kind}:/src/app/node_modules",
    '-v', "${Prefix}-npm:/cache/npm",
    '-v', "${Prefix}-tools-${Kind}:/root/.cache",
    '-e', 'CARGO_TARGET_DIR=/cache/target', '-e', 'npm_config_cache=/cache/npm', '-e', 'CI=true',
    '-e', "HELIX_RELEASE=$(if ($Release) { 1 } else { 0 })")
  if ($Out) {
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    $runArgs += @('-v', "$((Resolve-Path $Out).Path):/out", '-e', 'HELIX_OUT=/out')
  }
  $runArgs += $Extra
  $runArgs += @('-w', '/src', $image, 'sh', $Script)
  $runArgs += $ScriptArgs
  & docker @runArgs
  if ($LASTEXITCODE -ne 0) { Fail "$Script failed in the $Kind container" }
}

function Build-Android {
  $keystore = if ($env:HELIX_ANDROID_KEYSTORE) { $env:HELIX_ANDROID_KEYSTORE } else { Join-Path $HOME '.awake-helix-signing\android-release.jks' }
  $passwordFile = if ($env:HELIX_ANDROID_KEYSTORE_PASSWORD_FILE) { $env:HELIX_ANDROID_KEYSTORE_PASSWORD_FILE } else { [System.IO.Path]::ChangeExtension($keystore, '.password') }
  $alias = if ($env:HELIX_ANDROID_KEY_ALIAS) { $env:HELIX_ANDROID_KEY_ALIAS } else { '' }
  $dir = Split-Path -Parent $keystore
  if ($dir.StartsWith($Rs, [System.StringComparison]::OrdinalIgnoreCase)) { Fail "the Android keystore must live outside the repository ($keystore)" }
  # Also outside a repository this one is checked out in (as a submodule).
  $super = ''
  if (Get-Command git -ErrorAction SilentlyContinue) { $super = (git -C $Rs rev-parse --show-superproject-working-tree 2> $null | Select-Object -First 1) }
  if ($super) {
    $super = [System.IO.Path]::GetFullPath($super)
    if ($dir.StartsWith($super, [System.StringComparison]::OrdinalIgnoreCase)) { Fail "the Android keystore must live outside the repository ($keystore is inside $super)" }
  }
  if ((Split-Path -Parent $passwordFile) -ne $dir) { Fail "keep the keystore password file next to the keystore ($dir)" }
  $generate = -not (Test-Path $keystore)
  if ($generate) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # Only this user may read the signing directory.
    icacls $dir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
  }
  if (-not $NoEmulator) { Say 'the emulator smoke test needs /dev/kvm (Linux hosts); skipped under Docker Desktop' }
  Need-Disk 8
  $extra = @('-v', "${dir}:/signing",
    '-e', "HELIX_ANDROID_KEYSTORE=/signing/$(Split-Path -Leaf $keystore)",
    '-e', "HELIX_ANDROID_KEYSTORE_PASSWORD_FILE=/signing/$(Split-Path -Leaf $passwordFile)",
    '-e', "HELIX_ANDROID_KEY_ALIAS=$alias",
    '-e', "HELIX_ANDROID_GENERATE=$(if ($generate) { 1 } else { 0 })",
    '-v', "${Prefix}-gradle:/cache/gradle")
  Run-In 'android' $extra 'build/scripts/android.sh' @()
  if ($generate -and (Test-Path $keystore)) {
    Write-Host ''
    Write-Host '################################################################################' -ForegroundColor Yellow
    Write-Host "#  A NEW ANDROID RELEASE SIGNING KEY WAS CREATED: $keystore" -ForegroundColor Yellow
    Write-Host "#  and its password file $passwordFile." -ForegroundColor Yellow
    Write-Host '#  BACK BOTH UP NOW (offline). Every future update must be signed with this key;' -ForegroundColor Yellow
    Write-Host '#  if it is lost, installed apps can never be updated. Never commit it.' -ForegroundColor Yellow
    Write-Host '################################################################################' -ForegroundColor Yellow
  }
}

$lock = Join-Path ([System.IO.Path]::GetTempPath()) "$Prefix-build.lock"
try { New-Item -ItemType Directory -Path $lock -ErrorAction Stop | Out-Null } catch { Fail "another build holds $lock (remove it if no build runs)" }
try {
  switch ($Platform) {
    'linux' { Need-Disk 6; Run-In 'linux' @() 'build/scripts/linux.sh' @('app') }
    'cli-linux' { Need-Disk 3; Run-In 'linux' @() 'build/scripts/linux.sh' @('cli') }
    'windows' { Need-Disk 6; Run-In 'windows' @() 'build/scripts/windows.sh' @('app') }
    'cli-windows' { Need-Disk 3; Run-In 'windows' @() 'build/scripts/windows.sh' @('cli') }
    'android' { Build-Android }
    { $_ -in @('all', 'all-linux-host') } {
      if ($Out) { Fail "$Platform writes to dist/<platform>; -Out is not supported" }
      Need-Disk 6; Run-In 'linux' @() 'build/scripts/linux.sh' @('app')
      Run-In 'windows' @() 'build/scripts/windows.sh' @('app')
      Build-Android
      if ($Platform -eq 'all') { Say 'macos and ios skipped: they build only on a Mac (run ./build.sh all there)' }
      Say "done. Release files (with .sha256 and SHA256SUMS) are in $(Join-Path $Rs 'dist')\{linux,windows,android}"
    }
    'test' { Need-Disk 6; Run-In 'linux' @() 'build/scripts/test.sh' @() }
    'images' { foreach ($kind in 'linux', 'windows', 'android') { Say "image: $(Image-For $kind)" } }
    'clean' { $KeepCache = $false }
  }
} finally {
  if ($Platform -ne 'images') { Invoke-Cleanup }
  if (Test-Path $lock) { Remove-Item $lock -Force }
}
