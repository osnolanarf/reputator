<p align="center">
  <img src="https://github.com/osnolanarf/reputator/blob/main/reputator_logo.png?raw=true" alt="REPUTATOR logo" width="300"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-blue?style=flat-square" alt="PowerShell">
  <img src="https://img.shields.io/badge/GPL--3.0-License-green?style=flat-square" alt="License: GPL-3.0">
  <img src="https://img.shields.io/badge/Version-2.3-lightgrey?style=flat-square" alt="Version 2.3">
</p>


> 🇬🇧 [View this README in English](README.en.md)

---

<img width="1000" alt="reputatorhash" src="https://github.com/cybevner/reputator/assets/59768231/dd63bc55-0298-4a6c-bb97-a4fe6aadcb5f">

## 🔍 Descripción

`Reputator` es un script en PowerShell que permite consultar la reputación de hashes, direcciones IP o dominios utilizando [`VirusTotal`](https://www.virustotal.com/) y [`Hybrid Analysis`](https://www.hybrid-analysis.com/). Muestra los resultados en una tabla en consola con colores para una interpretación rápida.

Inspirado en [`Malwoverview`](https://github.com/alexandreborges/malwoverview), `Reputator` simplifica el análisis desde PowerShell, sin dependencias externas como Python ni necesidad de entornos virtuales como [`REMnux`](https://remnux.org/).

---

## ⚙️ Opciones de uso

Ejecutar `reputator.ps1` con una de las siguientes opciones:

- `-h` : Analizar un listado de **hashes**.
- `-i` : Analizar un listado de **IPs**.
- `-d` : Analizar un listado de **dominios**.
- `-help` : Mostrar la ayuda del script.

---

## 📦 Requisitos

- API key válida de [VirusTotal](https://developers.virustotal.com/reference/getting-started).
- API key válida de [Hybrid Analysis](https://www.hybrid-analysis.com/docs/api/v2).
- Archivo `.txt` con los indicadores a analizar.
- Módulo PowerShell [`PSWriteColor`](https://www.powershellgallery.com/packages/PSWriteColor):

```powershell
Install-Module -Name PSWriteColor -Force
```

---

## ▶️ Ejemplos de ejecución

```powershell
reputator.ps1 -h -hashFile "C:\ruta\a\hashes.txt"
reputator.ps1 -i -ipFile "C:\ruta\a\ips.txt"
reputator.ps1 -d -domainFile "C:\ruta\a\domains.txt"
```

---

## 🖥️ Añadir a PATH (opcional)

Para ejecutar `reputator.ps1` desde cualquier terminal:

1. Abre "Editar variables de entorno del sistema".
2. En "Variables del sistema", edita `Path` y añade la ruta donde está el script.
3. Abre una nueva ventana de terminal.

O desde línea de comandos:

```cmd
setx PATH "%PATH%;C:\ruta\del\script" /M
```

---

## 🧪 Salida esperada

### Hashes

```
MUESTRA   HASH                                VT NOMBRE   VT DETECCIONES   VT PRIMER ANALISIS   VT ULTIMO ANALISIS   HYBRID-ANALYSIS
Hash_1    ...                                 archivo.exe 65               2015-05-15            2023-10-01           malicious
```

### IPs

```
MUESTRA   IP             PAÍS   DETECCIONES   PRIMER ANALISIS   ÚLTIMO ANALISIS
IP_1      45.133.5.148   AU     0             N/A                N/A
```

### Dominios

```
MUESTRA   DOMINIO              DETECCIONES   CREACIÓN           ÚLTIMO ANALISIS
Dom_1     ejemplo.com          12            2023-06-28         2023-07-27
```

---

## 📌 Historial de versiones

### v2.3
- Validación de entradas (hashes, IPs, dominios).
- Salida coloreada (verde/rojo).
- Parámetros para rutas de archivo.

### v2.2
- Columna `VT NOMBRE` añadida.

### v2.1
- Manejo de errores si el hash no existe en VirusTotal.

### v2.0
- Consulta a Hybrid Analysis añadida.

### v1.0
- Consultas a VirusTotal para hashes, IPs y dominios.

---

## 🤝 Créditos

- Inspirado en [`Malwoverview`](https://github.com/alexandreborges/malwoverview)
- Desarrollado para analistas SOC, blue team y DFIR.

---

## ⭐ Colabora

¿Te ha resultado útil? ¡Dale una ⭐ al repositorio!

Sugerencias, ideas o pull requests son bienvenidos.



