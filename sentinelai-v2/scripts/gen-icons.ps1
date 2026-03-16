Add-Type -AssemblyName System.Drawing

$outDir = "c:\ai security\sentinelai-v2\icons"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

foreach ($size in @(16, 48, 128)) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.SmoothingMode = 'AntiAlias'
    $graphics.Clear([System.Drawing.Color]::FromArgb(10, 14, 26))

    $lineWidth = [Math]::Max(1, [int]($size * 0.06))
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 229, 255), $lineWidth)
    $radius = [int]($size * 0.35)
    $center = [int]($size / 2)

    $graphics.DrawEllipse($pen, ($center - $radius), ($center - $radius), ($radius * 2), ($radius * 2))

    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 229, 255))
    $innerR = [int]($size * 0.12)
    $graphics.FillEllipse($brush, ($center - $innerR), ($center - $innerR), ($innerR * 2), ($innerR * 2))

    $filePath = "$outDir\icon-$size.png"
    $bmp.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bmp.Dispose()
    Write-Host "Created $filePath"
}

Write-Host "Done!"
