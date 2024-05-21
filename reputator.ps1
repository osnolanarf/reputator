<#
Derechos de autor (C) 2023 Francisco Alonso <fran.alonsoplaza@gmail.com>

Este programa es software libre: puede redistribuirlo y/o modificarlo
bajo los términos de la Licencia Pública General de GNU publicada por
la Fundación para el Software Libre, ya sea la versión 3 de la Licencia,
o (a su elección) cualquier versión posterior.

Este programa se distribuye con la esperanza de que sea útil,
pero SIN GARANTÍA ALGUNA; ni siquiera la garantía implícita de
COMERCIABILIDAD o ADECUACIÓN PARA UN PROPÓSITO PARTICULAR. Consulte
la Licencia Pública General de GNU para obtener más detalles.

Vea la Licencia Pública General de GNU en <http://www.gnu.org/licenses/>.

COLABORADORES

Fran Alonso (propietario del proyecto)

reputator.ps1: version 2.3
#>

param (
    [switch]$h,       # Para revisar una lista de hashes desde un fichero txt
    [switch]$i,       # Para revisar una lista de IPs desde un fichero txt
    [switch]$d,       # Para revisar una lista de dominios desde un fichero txt
    [switch]$help,    # Para mostrar la ayuda
    [string]$hashFile = "C:\RUTA\ARCHIVO\hashes.txt",
    [string]$ipFile = "C:\RUTA\ARCHIVO\ips.txt",
    [string]$domainFile = "C:\RUTA\ARCHIVO\domains.txt"
)

function Show-Help {
    Write-Output @"
Ejecutar reputator.ps1 con una de las siguientes opciones:

-h para indicar que se le va a proporcionar un listado de hashes.
-i para indicar que se le va a proporcionar un listado de direcciones IP.
-d para indicar que se le va a proporcionar un listado de dominios.

Tambien puede especificar las rutas de los archivos con los siguientes parametros:
-hashFile [ruta]  : Ruta del archivo que contiene los hashes.
-ipFile [ruta]    : Ruta del archivo que contiene las direcciones IP.
-domainFile [ruta]: Ruta del archivo que contiene los dominios.

Ejemplo de uso:
.\reputator.ps1 -h -hashFile "C:\windows\archivo\hashes.txt"
.\reputator.ps1 -i -ipFile "C:\windows\archivo\ips.txt"
.\reputator.ps1 -d -domainFile "C:\windows\archivo\domains.txt"
"@
}

if ($help) {
    Show-Help
    return
}

if (-not ($h -or $i -or $d)) {
    Write-Output "Error: Debe seleccionar al menos una opcion valida. Use la opcion `-help` para mostrar la ayuda."
    return
}

# Importar el módulo PSWriteColor
Import-Module PSWriteColor

# API Keys
$apiKey = "TU_API_AKI"
$hybridApiKey = "TU_API_AKI"

# Funciones de colores
function Write-Red {
    param([string]$text)
    $escape = [char]27
    return "$escape[31m$text$escape[0m"
}

function Write-Green {
    param([string]$text)
    $escape = [char]27
    return "$escape[32m$text$escape[0m"
}

function Write-Yellow {
    param([string]$text)
    $escape = [char]27
    return "$escape[33m$text$escape[0m"
}

function Write-Blue {
    param([string]$text)
    $escape = [char]27
    return "$escape[34m$text$escape[0m"
}

# Funciones de validación
function Validate-Hash {
    param ([string]$hash)
    return ($hash -match '^[a-fA-F0-9]{64}$')
}

function Validate-Ip {
    param ([string]$ip)
    return ($ip -match '^(?:\d{1,3}\.){3}\d{1,3}$' -or $ip -match '^[a-fA-F0-9:]+$')
}

function Validate-Domain {
    param ([string]$domain)
    return ($domain -match '^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
}

function Validate-FileContent {
    param (
        [string[]]$content,
        [scriptblock]$validationFunction
    )

    foreach ($item in $content) {
        if (-not (&$validationFunction $item)) {
            Write-Output "Entrada no valida encontrada: $item"
            return $false
        }
    }
    return $true
}

function Get-HybridAnalysis {
    param ([string]$hash)

    $headers = @{
        "accept" = "application/json"
        "user-agent" = "Falcon Sandbox"
        "api-key" = $hybridApiKey
    }
    $url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    $body = @{ "hash" = $hash }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
        return $response[0].verdict
    }
    catch {
        return "N/A"
    }
}

function Get-Reputation {
    param ([string]$type, [string]$value)

    $headers = @{ "x-apikey" = $apiKey }
    $url = "https://www.virustotal.com/api/v3/$type/$value"

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        return $response
    }
    catch {
        return $null
    }
}

function Get-FileReputation {
    param (
        [string]$hash
    )

    $headers = @{
        "x-apikey" = $apiKey
    }
    $url = "https://www.virustotal.com/api/v3/files/$hash"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        if ($response) {
            $lastAnalysisStats = $response.data.attributes.last_analysis_stats
            $positives = $lastAnalysisStats.malicious
            $firstAnalysisDate = [System.DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.first_submission_date).DateTime
            $lastAnalysisDate = [System.DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.last_analysis_date).DateTime
            $fileName = $response.data.attributes.names[0]

            # Crear objeto personalizado con la información del hash
            $hashInfo = [PSCustomObject]@{
                Muestra = "Hash_$($hashList.IndexOf($hash) + 1)"
                Hash = $hash
                NOMBRE = $fileName  # Agregar la propiedad NOMBRE
                "AV DETECCIONES" = $positives
                "Fecha Primer Análisis" = if ($firstAnalysisDate.Year -eq 1970) { "N/A" } else { $firstAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
                "Fecha Último Análisis" = if ($lastAnalysisDate.Year -eq 1970) { "N/A" } else { $lastAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
                "HYBRID-ANALYSIS" = "N/A"
            }

            # Obtener resultado de Hybrid Analysis
            $hybridMalicious = Get-HybridAnalysis -hash $hash
            $hashInfo."HYBRID-ANALYSIS" = $hybridMalicious

            return $hashInfo
        }
        else {
            # En caso de que el hash no exista, asignar "N/A" a las propiedades de VirusTotal y "NOMBRE"
            $hashInfo = [PSCustomObject]@{
                Muestra = "Hash_$($hashList.IndexOf($hash) + 1)"
                Hash = $hash
                NOMBRE = "N/A"  # Asignar "N/A" como nombre si no se encuentra
                "AV DETECCIONES" = "N/A"
                "Fecha Primer Análisis" = "N/A"
                "Fecha Último Análisis" = "N/A"
                "HYBRID-ANALYSIS" = "N/A"
            }
            return $hashInfo
        }
    }
    catch {
        # En caso de error, asignar "N/A" a las propiedades de VirusTotal y "NOMBRE"
        $hashInfo = [PSCustomObject]@{
            Muestra = "Hash_$($hashList.IndexOf($hash) + 1)"
            Hash = $hash
            NOMBRE = "N/A"  # Asignar "N/A" como nombre si no se encuentra
            "AV DETECCIONES" = "N/A"
            "Fecha Primer Análisis" = "N/A"
            "Fecha Último Análisis" = "N/A"
            "HYBRID-ANALYSIS" = "N/A"
        }
        return $hashInfo
    }
}

function Format-Date {
    param ([int]$timestamp)

    $date = [System.DateTimeOffset]::FromUnixTimeSeconds($timestamp).DateTime
    if ($date.Year -eq 1970) { 
        return "N/A"
    } else { 
        return $date.ToString("yyyy-MM-dd HH:mm:ss") 
    }
}

function Process-Results {
    param (
        [string]$type,
        [string[]]$list,
        [scriptblock]$validationFunction
    )

    if (-not (Validate-FileContent -content $list -validationFunction $validationFunction)) {
        return
    }

    $results = @()

    foreach ($item in $list) {
        $response = Get-Reputation -type $type -value $item

        if ($response) {
            $info = [PSCustomObject]@{
                Muestra = "$type_$($list.IndexOf($item) + 1)"
                Valor = $item
                NOMBRE = if ($type -eq "files") { $response.data.attributes.names[0] } else { $null }
                "AV DETECCIONES" = $response.data.attributes.last_analysis_stats.malicious
                "Fecha Primer Análisis" = Format-Date $response.data.attributes.first_submission_date
                "Fecha Último Análisis" = Format-Date $response.data.attributes.last_analysis_date
                "HYBRID-ANALYSIS" = if ($type -eq "files") { Get-HybridAnalysis -hash $item } else { "N/A" }
            }
            $results += $info
        } else {
            $results += [PSCustomObject]@{
                Muestra = "$type_$($list.IndexOf($item) + 1)"
                Valor = $item
                NOMBRE = if ($type -eq "files") { "N/A" } else { $null }
                "AV DETECCIONES" = "N/A"
                "Fecha Primer Análisis" = "N/A"
                "Fecha Último Análisis" = "N/A"
                "HYBRID-ANALYSIS" = "N/A"
            }
        }
    }

    if ($type -eq "files") {
        $results | ForEach-Object {
            $vtDetections = $_."AV DETECCIONES"
            $hybridAnalysis = $_."HYBRID-ANALYSIS"

            if ($vtDetections -ne "N/A") {
                if ([int]$vtDetections -eq 0) {
                    $_."AV DETECCIONES" = Write-Green $vtDetections
                } elseif ([int]$vtDetections -gt 0) {
                    $_."AV DETECCIONES" = Write-Red $vtDetections
                }
            }

            if ($hybridAnalysis -eq "malicious") {
                $_."HYBRID-ANALYSIS" = Write-Red $hybridAnalysis
            }

            $_
        } | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "HASH"; Expression = { $_.Valor.PadRight(64) }},
            @{Label = "NOMBRE"; Expression = { $_.NOMBRE.PadRight(25) }},
            @{Label = "VT DETECCIONES"; Expression = { $_."AV DETECCIONES".PadRight(25) }},
            @{Label = "VT PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(25) }},
            @{Label = "VT ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis".PadRight(25) }},
            @{Label = "HYBRID-ANALYSIS"; Expression = { $_."HYBRID-ANALYSIS" }}
    } elseif ($type -eq "ip_addresses") {
        $results | ForEach-Object {
            $vtDetections = $_."AV DETECCIONES"
            $hybridAnalysis = $_."HYBRID-ANALYSIS"

            if ($vtDetections -ne "N/A") {
                if ([int]$vtDetections -eq 0) {
                    $_."AV DETECCIONES" = Write-Green $vtDetections
                } elseif ([int]$vtDetections -gt 0) {
                    $_."AV DETECCIONES" = Write-Red $vtDetections
                }
            }

            $_
        } | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "IP"; Expression = { $_.Valor.PadRight(64) }},
            @{Label = "VT DETECCIONES"; Expression = { $_."AV DETECCIONES".PadRight(25) }},
            @{Label = "VT PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(25) }},
            @{Label = "VT ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis".PadRight(25) }},
            @{Label = "HYBRID-ANALYSIS"; Expression = { $_."HYBRID-ANALYSIS" }}
    } elseif ($type -eq "domains") {
        $results | ForEach-Object {
            $vtDetections = $_."AV DETECCIONES"
            $hybridAnalysis = $_."HYBRID-ANALYSIS"

            if ($vtDetections -ne "N/A") {
                if ([int]$vtDetections -eq 0) {
                    $_."AV DETECCIONES" = Write-Green $vtDetections
                } elseif ([int]$vtDetections -gt 0) {
                    $_."AV DETECCIONES" = Write-Red $vtDetections
                }
            }

            $_
        } | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "DOMINIO"; Expression = { $_.Valor.PadRight(64) }},
            @{Label = "VT DETECCIONES"; Expression = { $_."AV DETECCIONES".PadRight(25) }},
            @{Label = "VT PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(25) }},
            @{Label = "VT ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis".PadRight(25) }},
            @{Label = "HYBRID-ANALYSIS"; Expression = { $_."HYBRID-ANALYSIS" }}
    }
}

if ($h) {
    if (-not (Test-Path -Path $hashFile)) {
        Write-Output "Error: El archivo de hashes $hashFile no existe."
        return
    }
    $hashList = Get-Content $hashFile
    Process-Results -type "files" -list $hashList -validationFunction ${function:Validate-Hash}
}

if ($i) {
    if (-not (Test-Path -Path $ipFile)) {
        Write-Output "Error: El archivo de IPs $ipFile no existe."
        return
    }
    $ipList = Get-Content $ipFile
    Process-Results -type "ip_addresses" -list $ipList -validationFunction ${function:Validate-Ip}
}

if ($d) {
    if (-not (Test-Path -Path $domainFile)) {
        Write-Output "Error: El archivo de dominios $domainFile no existe."
        return
    }
    $domainList = Get-Content $domainFile
    Process-Results -type "domains" -list $domainList -validationFunction ${function:Validate-Domain}
}
