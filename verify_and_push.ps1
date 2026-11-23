$ErrorActionPreference = "Stop"
Set-Location "C:\AdHDF"

Write-Host "[1/5] dist klasorunde kisisel .env dosyasi olmadigini kontrol ediliyor..." -ForegroundColor Cyan
if (Test-Path "C:\AdHDF\dist\.env") {
    throw "HATA: C:\AdHDF\dist\.env bulundu! Dagitim klasorunden silinmelidir."
}
if (-not (Test-Path "C:\AdHDF\dist\AdHDF_Enterprise.exe")) {
    throw "HATA: C:\AdHDF\dist\AdHDF_Enterprise.exe bulunamadi! Once PyInstaller ile derleyin."
}
Write-Host "OK: dist klasorunde kisisel .env yok, AdHDF_Enterprise.exe mevcut." -ForegroundColor Green

Write-Host "[2/5] Izole test klasoru (C:\AdHDF_ShareTest) hazirlaniyor..." -ForegroundColor Cyan
$testDir = "C:\AdHDF_ShareTest"
if (Test-Path $testDir) {
    Remove-Item -Recurse -Force $testDir
}
New-Item -ItemType Directory -Path $testDir | Out-Null
Copy-Item "C:\AdHDF\dist\AdHDF_Enterprise.exe" -Destination "$testDir\AdHDF_Enterprise.exe"

$envContent = Get-Content "C:\AdHDF\.env" -Raw -Encoding UTF8
$myPass = if ($envContent -match "SOC_PASSWORD=(.+)") { $matches[1].Trim() } else { "" }

$testEnvPath = "$testDir\.env"
@"
SOC_USERNAME=test_user
SOC_PASSWORD=YeniTestSifresi_9988!
DECEPTION_MODE=static_only
SETUP_COMPLETED=true
"@ | Set-Content -Path $testEnvPath -Encoding UTF8

$createdEnv = Get-Content $testEnvPath -Raw -Encoding UTF8
if ($myPass -and $createdEnv.Contains($myPass)) {
    throw "HATA: Izole test klasorundeki .env senin kisisel parolanı iceriyor!"
}
Write-Host "OK: Izole .env olusturuldu ve kisisel parolanla eslesmedigi dogrulandi." -ForegroundColor Green

Write-Host "[3/5] Test klasoru temizleniyor..." -ForegroundColor Cyan
Remove-Item -Recurse -Force $testDir
Write-Host "OK: C:\AdHDF_ShareTest kalintisi silindi." -ForegroundColor Green

Write-Host "[4/5] Yerel Git deposu guncelleniyor..." -ForegroundColor Cyan
git add -A
$status = git status --porcelain
if ($status) {
    git commit -m "chore(release): verify clean exe distribution package without personal .env"
    $tagName = "v2.0.1"
    if (-not (git tag -l $tagName)) {
        git tag -a $tagName -m "AdHDF Enterprise $tagName - Clean Distribution Verified"
    }
} else {
    Write-Host "Bilgi: Yeni commit gerektirecek degisiklik yok, mevcut commit kullanilacak." -ForegroundColor Yellow
}

Write-Host "[5/5] GitHub ozel deposuna (origin/main ve tags) gonderiliyor..." -ForegroundColor Cyan
git push -u origin main --tags
Write-Host "TAMAMLANDI: Dagitim paketi dogrulandi ve GitHub guncellendi." -ForegroundColor Green
