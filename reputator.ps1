param (
    [switch]$h, # Para revisar una lista de hashes desde un fichero txt
    [switch]$i, # Para revisar una lista de IPs desde un fichero txt
    [switch]$d # Para revisar una lista de dominios desde un fichero txt
)

# API de VirusTotal
$apiKey = "000000000000000000000000000000000000000000"

function Get-FileReputation {
    param (
        [string]$hash
    )

    $headers = @{
        "x-apikey" = $apiKey
    }
    $url = "https://www.virustotal.com/api/v3/files/$hash"
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
            "AV Detecciones" = $positives
            "Fecha Primer Análisis" = if ($firstAnalysisDate.Year -eq 1970) { "N/A" } else { $firstAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
            "Fecha Último Análisis" = if ($lastAnalysisDate.Year -eq 1970) { "N/A" } else { $lastAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss") }
        }

        return $hashInfo
    }
    else {
        Write-Output "No se pudo obtener la reputación para el hash: $hash"
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
            "AV Detecciones" = $positives
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
    $hashFile = "C:\tu\ruta\ficheros\hashes.txt"

    # Verificar que el archivo exista
    if (Test-Path -Path $hashFile) {
        # Leer el contenido del archivo
        $hashList = Get-Content $hashFile

        # Crear una lista para almacenar los resultados
        $results = @()

        # Iterar por cada hash y obtener su reputación
        foreach ($hash in $hashList) {
            $result = Get-FileReputation -hash $hash
            if ($result) {
                $results += $result
            }
        }

        # Mostrar los resultados en una tabla con más espacio entre columnas
        $results | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "HASH"; Expression = { $_.Hash.PadRight(64) }},
            @{Label = "AV DETECCIONES"; Expression = { $_."AV Detecciones".ToString().PadRight(18) }},
            @{Label = "FECHA PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(26) }},
            @{Label = "FECHA ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis" }}
    }
    else {
        Write-Output "El archivo $hashFile no existe."
    }
}

if ($i) {
    # Ruta del archivo txt con las direcciones IP
    $ipFile = "C:\tu\ruta\ficheros\ips.txt"

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
        $results | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "IP"; Expression = { $_.IP.PadRight(20) }},
            @{Label = "PAIS"; Expression = { $_.Pais.PadRight(10) }},
            @{Label = "AV DETECCIONES"; Expression = { $_."AV Detecciones".ToString().PadRight(18) }},
            @{Label = "FECHA PRIMER ANALISIS"; Expression = { $_."Fecha Primer Análisis".PadRight(26) }},
            @{Label = "FECHA ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis" }}
    }
    else {
        Write-Output "El archivo $ipFile no existe."
    }
}

if ($d) {
    # Ruta del archivo txt con los dominios
    $domainFile = "C:\tu\ruta\ficheros\domains.txt"

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
        $results | Format-Table -AutoSize -Wrap `
            @{Label = "MUESTRA"; Expression = { $_.Muestra.PadRight(12) }},
            @{Label = "DOMINIO"; Expression = { $_.Dominio.PadRight(30) }},
            @{Label = "AV DETECCIONES"; Expression = { $_."AV Detecciones".ToString().PadRight(18) }},
            @{Label = "FECHA CREACION DOMINIO"; Expression = { $_."Fecha Creación Dominio".PadRight(26) }},
            @{Label = "FECHA ULTIMO ANALISIS"; Expression = { $_."Fecha Último Análisis" }}
    }
    else {
        Write-Output "El archivo $domainFile no existe."
    }
}