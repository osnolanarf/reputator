<p align="center">
  <img src="https://github.com/osnolanarf/reputator/blob/main/reputator_logo.png?raw=true" alt="REPUTATOR logo" width="600"/>
</p>



> 🇬🇧 [View this README in English](README.en.md)

---




<img width="1000" alt="reputatorhash" src="https://github.com/cybevner/reputator/assets/59768231/dd63bc55-0298-4a6c-bb97-a4fe6aadcb5f">


## Descripción

El objetivo de `Reputator` es simple: comprobar la reputación de un bloque de hashes, IPs o dominios en [`VirusTotal`](https://www.virustotal.com/) y devolver los resultados en una tabla.

La idea original surge de la herramienta [`Malwoverview`](https://github.com/alexandreborges/malwoverview) (mucho más completa y a años luz de lo que tienes delante, ¡revísala!) simplificando a un solo sitio, VirusTotal, y que pudiera ser ejecutado sin necesidad de dependencias de `Phyton` y sin tener que levantar un sistema virtual con [`Remnux`](https://remnux.org/) para comprobar la reputación de unos cuantos hashes.

Posteriormente, en la versión 2, se ha incluido el sitio [`Hybrid-Analysis`](https://www.hybrid-analysis.com/) para comprobar la reputación de los hashes, mostrándose el resultado en una nueva columna en la tabla.

## Funcionamiento

Ejecutar `reputator.ps1` con una de las siguientes opciones
- `-h` para indicar que se le va a proporcionar un listado de hashes.
- `-i` para indicar que se le va a proporcionar un listado de direcciones IP.
- `-d` para indicar que se le va a proporcionar un listado de dominios.
- `-help` : Para mostrar la ayuda.

## Requisitos

- Disponer de una API de [`VirusTotal`](https://developers.virustotal.com/reference/getting-started).
- Disponer de una API de [`Hybrid-Analysis`](https://www.hybrid-analysis.com/docs/api/v2).
- Modificar el script con la ruta donde tengamos el fichero de texto con los elementos que se quieran comprobar o bien indicarla en la ejecución del script. Por ejemplo:
```powershell
.\reputator.ps1 -h -hashFile "C:\ruta\a\hashes.txt"
.\reputator.ps1 -i -ipFile "C:\ruta\a\ips.txt"
.\reputator.ps1 -d -domainFile "C:\ruta\a\domains.txt"
```
- Disponer del módulo PSWriteColor: `Install-Module -Name PSWriteColor -Force`.

## Uso

A continuación, ejemplos de ejecución de `Reputator`:

- Comprobación de hashes.

```
C:\Users\test\Desktop>powershell.exe ./reputator.ps1 -h

MUESTRA      HASH                                                             VT NOMBRE                      VT DETECCIONES            VT PRIMER ANALISIS        VT ULTIMO ANALISIS        HYBRID-ANALYSIS
-------      ----                                                             ---------                      --------------            ------------------        ------------------        ---------------
Hash_1       00000075d77e227cdb2d386181e42f42b579eb16403143dc54cd4a3d17fc8622 lhgew.exe                      65                        2015-05-15 18:42:36       2023-10-01 05:22:31       malicious
Hash_2       0d7b9f1850db74b66b0b89af6ae89368600541f6bbfbbb2f6fed32ec44839699 deoakoy.exe                    62                        2015-05-30 11:00:25       2023-05-10 19:35:26       malicious
Hash_3       B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450 N/A                            N/A                       N/A                       N/A                       N/A
Hash_4       dcf5d6debde2d07ac911a86a68167dd44b538ee31eb66a48726a5b7327a2a7cc leifoi.exe                     50                        2015-12-25 11:16:38       2015-12-28 06:25:32       N/A
```


- Comprobación de IPs.

```
C:\Users\test\Desktop>powershell.exe ./reputator.ps1 -i

MUESTRA      IP                   PAIS       AV DETECCIONES VT PRIMER ANALISIS         VT ULTIMO ANALISIS
-------      --                   ----       -------------- ------------------         ------------------
IP_1         45.133.5.148         AU                      0 N/A                        N/A
IP_2         45.133.5.149         AU                      0 N/A                        2023-03-31 14:12:34
IP_3         45.133.5.143         AU                      0 N/A                        N/A
IP_4         45.133.5.115         AU                      0 N/A                        N/A
IP_5         35.205.61.67         BE                      4 N/A                        2023-08-01 01:19:58
IP_6         191.101.130.67       US                      0 N/A                        N/A
IP_7         45.133.5.106         AU                      0 N/A                        N/A
IP_8         45.133.5.145         AU                      0 N/A                        2023-04-05 14:57:06
IP_9         45.133.5.147         AU                      0 N/A                        N/A
IP_10        107.180.173.9        US                      0 N/A                        2023-07-14 13:14:28
IP_11        23.216.147.76        US                      1 N/A                        2023-08-01 00:01:28


```

- Comprobación de dominios.

```
C:\Users\test\Desktop>powershell.exe ./reputator.ps1 -d

MUESTRA      DOMINIO                        VT DETECCIONES     VT CREACION DOMINIO        VT ULTIMO ANALISIS
-------      -------                        --------------     -------------------        ------------------
Domain_1     finformservice.com             18                 2023-06-28 00:00:00        2023-07-27 20:15:13
Domain_2     altimata.org                   12                 2023-05-18 00:00:00        2023-07-20 15:47:36
Domain_3     penofach.com                   12                 2023-05-18 00:00:00        2023-07-20 15:47:36
Domain_4     bentaxworld.com                13                 2023-05-16 00:00:00        2023-07-20 18:45:13
Domain_5     wexonlake.com                  20                 2023-05-01 00:00:00        2023-07-27 11:01:18
Domain_6     ukrainianworldcongress.info    19                 2023-06-26 00:00:00        2023-07-31 01:10:21
Domain_7     marca.com                      0                  1997-03-12 05:00:00        2023-08-01 02:14:13
```

## Ejecución rápida

Crear una variable de entorno para ejecutar el script desde cualquier ubicación de cmd o powershell

1. Abre el menú de Inicio y busca "Editar las variables de entorno del sistema". Haz clic en el resultado que dice "Editar las variables de entorno del sistema".
    
2. Se abrirá una ventana de "Propiedades del sistema". Haz clic en el botón "Variables de entorno" en la parte inferior de la ventana.
    
3. En la sección "Variables del sistema", busca la variable llamada "Path" y selecciónala. Luego, haz clic en el botón "Editar".
    
4. Aparecerá una nueva ventana llamada "Editar variable del sistema". Haz clic en "Nuevo" para agregar una nueva ruta.
    
5. Escribe la ruta completa del directorio que contiene `reputator.ps1`. Luego, haz clic en "Aceptar" para cerrar todas las ventanas.
    
6. Asegúrate de abrir una nueva ventana del símbolo del sistema (cmd) después de hacer estos cambios, ya que los cambios en las variables de entorno no se aplicarán a las ventanas de cmd ya abiertas.

Alternativa:

```cmd
setx PATH "%PATH%;C:\tu\ruta\scripts" /M

```

## Historial

Versión 2.3

```
Esta versión incluye:

* Se ha implementado la validación de entradas para hashes, direcciones IP y dominios antes de procesarlas.
* Se ha añadido la funcionalidad de mostrar las detecciones en colores:
    * Rojo para detecciones maliciosas.
    * Verde para ausencia de detecciones.
* Se permite la configuración de las rutas de los archivos de entrada mediante parámetros.

```

Versión 2.2

```
Esta versión incluye:

* Se añade una columna "VT NOMBRE" para la consulta de hashes para añadir el nombre de cada hash según VirusTotal.

```

Versión 2.1

```
Esta versión incluye:

* Soluciona el problema de errores cuando el hash no existe en VirusTotal

```

Versión 2.0

```
Esta versión incluye:

* Consulta la reputación de hashes en Hybrid-Analysis.
* Mensaje de error en caso de ejecución incorrecta.
* Mensaje de ayuda.
* Color para las detecciones maliciosas.

```

Versión 1.0

```
Reputator es una herramienta de consulta de reputación de IOCs en VirusTotal.

* Consulta una lista de hashes en VT obteniendo su veredicto, fecha de primer scan y fecha de último scan.
* Consulta una lista de direcciones IP en VT obteniendo su veredicto, país, fecha de primer scan y fecha de último scan.
* Consulta una lista de dominios VT obteniendo su veredicto, fecha de primer scan y fecha de último scan.

```



