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


reputator.ps1: version 2

#>


param (
    [switch]$h, # Para revisar una lista de hashes desde un fichero txt
    [switch]$i, # Para revisar una lista de IPs desde un fichero txt
    [switch]$d, # Para revisar una lista de dominios desde un fichero txt
    [switch]$help # Para mostrar la ayuda
)

# Si se especifica la opción -help, mostrar el menú de ayuda y salir
if ($help) {
    Write-Output @"
Ejecutar reputator.ps1 con una de las siguientes opciones

-h para indicar que se le va a proporcionar un listado de hashes.
-i para indicar que se le va a proporcionar un listado de direcciones IP.
-d para indicar que se le va a proporcionar un listado de dominios.
"@
    return
}

# Si no se selecciona ninguna opción válida, mostrar un error y salir
if (-not ($h -or $i -or $d)) {
    Write-Output "Error: Debe seleccionar al menos una opcion valida. Use la opcion `-help` para mostrar la ayuda."
    return
}
# Importar el módulo PSWriteColor

Import-Module PSWriteColor

# API de VirusTotal
$apiKey = "TU_API_AKI"


# API de Hybrid Analysis
$hybridApiKey = "TU_API_AKI"

# Función para escribir texto en color rojo usando ANSI escape codes
function Write-Red {
    param([string]$text)
    $escape = [char]27
    Write-Output "$escape[31m$text$escape[0m"
}

function Get-HashHybridAnalysis {
    param (
        [string]$hash
    )

    $headers = @{
        "accept" = "application/json"
        "user-agent" = "Falcon Sandbox"
        "api-key" = $hybridApiKey
    }
    $url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    $body = @{
        "hash" = $hash
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
        if ($response -and $response.Count -gt 0) {
            $hybridMalicious = $response[0].verdict
        } else {
            $hybridMalicious = "N/A"
        }
    }
    catch {
        $hybridMalicious = "N/A"
    }

    return $hybridMalicious
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

            # Crear objeto personalizado con la información del hash
            $hashInfo = [PSCustomObject]@{
                Muestra = "Hash_$($hashList.IndexOf($hash) + 1)"
                Hash = $hash
                "AV DETECCIONES" = $positives
                "Fecha Primer Análisis" = if ($firstAnalysisDate.Year -eq 1970) { "N/A" } else { $firstAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
                "Fecha Último Análisis" = if ($lastAnalysisDate.Year -eq 1970) { "N/A" } else { $lastAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
                "HYBRID-ANALYSIS" = "N/A" # Inicializar la propiedad HYBRID-ANALYSIS
            }

            # Obtener resultado de Hybrid Analysis
            $hybridMalicious = Get-HashHybridAnalysis -hash $hash
            $hashInfo."HYBRID-ANALYSIS" = $hybridMalicious

            return $hashInfo
        }
        else {
            # En caso de que el hash no exista, asignar "N/A" a las propiedades de VirusTotal
            $hashInfo = [PSCustomObject]@{
                Muestra = "Hash_$($hashList.IndexOf($hash) + 1)"
                Hash = $hash
                "AV DETECCIONES" = "N/A"
                "Fecha Primer Análisis" = "N/A"
                "Fecha Último Análisis" = "N/A"
                "HYBRID-ANALYSIS" = "N/A" # Inicializar la propiedad HYBRID-ANALYSIS
            }
            return $hashInfo
        }
    }
    catch {
        # En caso de error, asignar "N/A" a las propiedades de VirusTotal
        $hashInfo = [PSCustomObject]@{
            Muestra = "Hash_$($hashList.IndexOf($hash) + 1)"
            Hash = $hash
            "AV DETECCIONES" = "N/A"
            "Fecha Primer Análisis" = "N/A"
            "Fecha Último Análisis" = "N/A"
            "HYBRID-ANALYSIS" = "N/A" # Inicializar la propiedad HYBRID-ANALYSIS
        }
        return $hashInfo
    }
}

function Get-IpReputation {
    param (
        [string]$ip
    )

    $headers = @{
        "x-apikey" = $apiKey
    }
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

    if ($response) {
        $lastAnalysisStats = $response.data.attributes.last_analysis_stats
        $positives = $lastAnalysisStats.malicious
        $firstAnalysisDate = [System.DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.first_submission_date).DateTime
        $lastAnalysisDate = [System.DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.last_analysis_date).DateTime

        # Crear objeto personalizado con la información de la IP
        $ipInfo = [PSCustomObject]@{
            Muestra = "IP_$($ipList.IndexOf($ip) + 1)"
            IP = $ip
            Pais = $response.data.attributes.country
            "AV Detecciones" = $positives
            "Fecha Primer Análisis" = if ($firstAnalysisDate.Year -eq 1970) { "N/A" } else { $firstAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
            "Fecha Último Análisis" = if ($lastAnalysisDate.Year -eq 1970) { "N/A" } else { $lastAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
        }

        return $ipInfo
    }
    else {
        Write-Output "No se pudo obtener la reputación para la IP: $ip"
    }
}

function Get-DomainReputation {
    param (
        [string]$domain
    )

    $headers = @{
        "x-apikey" = $apiKey
    }
    $url = "https://www.virustotal.com/api/v3/domains/$domain"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

    if ($response) {
        $creationDate = [System.DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.creation_date).DateTime
        $lastAnalysisStats = $response.data.attributes.last_analysis_stats
        $positives = $lastAnalysisStats.malicious
        $lastAnalysisDate = [System.DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.last_analysis_date).DateTime

        # Crear objeto personalizado con la información del dominio
        $domainInfo = [PSCustomObject]@{
            Muestra = "Domain_$($domainList.IndexOf($domain) + 1)"
            Dominio = $domain
            "AV DETECCIONES" = $positives
            "Fecha Creación Dominio" = if ($creationDate.Year -eq 1970) { "N/A" } else { $creationDate.ToString("yyyy-MM-dd HH:mm:ss") }
            "Fecha Último Análisis" = if ($lastAnalysisDate.Year -eq 1970) { "N/A" } else { $lastAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
        }

        return $domainInfo
    }
    else {
        Write-Output "No se pudo obtener la reputación para el dominio: $domain"
    }
}

if ($h) {
    # Ruta del archivo txt con los hashes
    $hashFile = "C:\RUTA\ARCHIVO\hashes.txt"

    # Verificar que el archivo exista
    if (Test-Path -Path $hashFile) {
        # Leer el contenido del archivo
        $hashList = Get-Content $hashFile

        # Crear una lista para almacenar los resultados
        $results = @()

        # Iterar por cada hash y obtener su reputación de VirusTotal y Hybrid Analysis
        foreach ($hash in $hashList) {
            $result = Get-FileReputation -hash $hash
            if ($result) {
                $results += $result
            }
        }

        # Mostrar los resultados en una tabla con más espacio entre columnas
        $results | ForEach-Object {
            $vtDetections = $_."AV DETECCIONES"
            $hybridAnalysis = $_."HYBRID-ANALYSIS"

            if ($vtDetections -ne "N/A") {
                if ([int]$vtDetections -eq 0) {
                    # Convertir el valor 0 a una cadena para que se muestre en la tabla
                    $_."AV DETECCIONES" = "0"
                } elseif ([int]$vtDetections -gt 0) {
                    # Aplicar formato de color rojo a las detecciones maliciosas en VirusTotal
                    $_."AV DETECCIONES" = (Write-Red $vtDetections)
                }
            }

            if ($hybridAnalysis -eq "malicious") {
                # Aplicar formato de color rojo al texto "malicious" en la columna "HYBRID-ANALYSIS"
                $_ | Add-Member -NotePropertyName "HYBRID-ANALYSIS" -NotePropertyValue (Write-Red $hybridAnalysis) -Force
            }

            $_
        } | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "HASH"; Expression = { $_.Hash.PadRight(64) }},
            @{Label = "VT DETECCIONES"; Expression = { $_."AV DETECCIONES".PadRight(25) }},
            @{Label = "VT PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(25) }},
            @{Label = "VT ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis".PadRight(25) }},
            @{Label = "HYBRID-ANALYSIS"; Expression = { $_."HYBRID-ANALYSIS" }}
    }
    else {
        Write-Output "El archivo $hashFile no existe."
    }
}

if ($i) {
    # Ruta del archivo txt con las direcciones IP
    $ipFile = "C:\RUTA\ARCHIVO\ips.txt"

    # Verificar que el archivo exista
    if (Test-Path -Path $ipFile) {
        # Leer el contenido del archivo
        $ipList = Get-Content $ipFile

        # Crear una lista para almacenar los resultados
        $results = @()

        # Iterar por cada dirección IP y obtener su reputación
        foreach ($ip in $ipList) {
            $result = Get-IpReputation -ip $ip
            if ($result) {
                $results += $result
            }
        }

    # Mostrar los resultados en una tabla con más espacio entre columnas
    $results | ForEach-Object {
        $vtDetections = $_."AV DETECCIONES"

        if ($vtDetections -ne "N/A") {
            if ([int]$vtDetections -gt 0) {
                # Aplicar formato de color rojo a las detecciones maliciosas en VirusTotal
                $_."AV DETECCIONES" = (Write-Red $vtDetections)
            }
            # Dejar el valor sin formato si las detecciones son 0
        }
        $_
    } | Format-Table -AutoSize -Wrap `
        @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
        @{Label = "IP"; Expression = { $_.IP.PadRight(20) }},
        @{Label = "PAIS"; Expression = { $_.Pais.PadRight(10) }},
        @{Label = "AV DETECCIONES"; Expression = { $_."AV DETECCIONES" }},  # Mantener el mismo formato de label que en la tabla de hashes
        @{Label = "VT PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(26) }},
        @{Label = "VT ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis" }}
}
else {
    Write-Output "El archivo $ipFile no existe."
}
}

if ($d) {
    # Ruta del archivo txt con los dominios
    $domainFile = "C:\RUTA\ARCHIVO\domains.txt"

    # Verificar que el archivo exista
    if (Test-Path -Path $domainFile) {
        # Leer el contenido del archivo
        $domainList = Get-Content $domainFile

        # Crear una lista para almacenar los resultados
        $results = @()

        # Iterar por cada dominio y obtener su reputación
        foreach ($domain in $domainList) {
            $result = Get-DomainReputation -domain $domain
            if ($result) {
                $results += $result
            }
        }

        # Mostrar los resultados en una tabla con más espacio entre columnas
        $results | ForEach-Object {
            $vtDetections = $_."AV DETECCIONES"
            if ($vtDetections -ne "N/A") {
                if ([int]$vtDetections -eq 0) {
                    # Convertir el valor 0 a una cadena para que se muestre en la tabla
                    $_."AV DETECCIONES" = "0"
                } elseif ([int]$vtDetections -gt 0) {
                    # Aplicar formato de color rojo a las detecciones maliciosas en VirusTotal
                    $_."AV DETECCIONES" = (Write-Red $vtDetections)
                }
            }
            $_
        } | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "DOMINIO"; Expression = { $_.Dominio.PadRight(30) }},
            @{Label = "VT DETECCIONES"; Expression = { $_."AV DETECCIONES".PadRight(18) }},
            @{Label = "VT CREACION DOMINIO"; Expression = { $_."Fecha Creación Dominio".PadRight(26) }},
            @{Label = "VT ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis" }}
    }
    else {
        Write-Output "El archivo $domainFile no existe."
    }
}
