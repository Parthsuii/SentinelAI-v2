Add-Type -AssemblyName System.Drawing

$outDir = Join-Path $PSScriptRoot ".." "icons"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

foreach ($size in @(16, 48, 128)) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::FromArgb(10, 14, 26))

    $lineWidth = [Math]::Max(1, [int]($size * 0.06))
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 229, 255), $lineWidth)
    $r = [int]($size * 0.35)
    $cx = [int]($size / 2)
    $cy = [int]($size / 2)

    $g.DrawEllipse($pen, ($cx - $r), ($cy - $r), ($r * 2), ($r * 2))

    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 229, 255))
    $cr = [int]($size * 0.12)
    $g.FillEllipse($brush, ($cx - $cr), ($cy - $cr), ($cr * 2), ($cr * 2))

    $filePath = Join-Path $outDir "icon-$size.png"
    $bmp.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Created $filePath"
}

Write-Host "Done!"
