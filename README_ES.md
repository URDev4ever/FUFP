<h1 align="center">FUFP — File Upload Fuzz Pack</h1>
<p align="center">
  🇺🇸 <a href="README.md"><b>English</b></a> |
  🇪🇸 <a href="README_ES.md">Español</a>
</p>

<h3 align="center">FUFP (File Upload Fuzz Pack) es una colección personal curada de archivos diseñada para probar, hacer fuzzing y analizar mecanismos de subida de archivos en aplicaciones web.</h3>

Se centra en vulnerabilidades comunes de subida de archivos, como filtrado incorrecto de extensiones, confusión de tipos MIME, bypass de magic bytes, dobles extensiones, trucos de codificación y riesgos de ejecución del lado del servidor.

> ⚠️ **Solo para pruebas de seguridad autorizadas.**

---

## 🎯 Propósito

Las funcionalidades de subida de archivos son una superficie de ataque frecuente en aplicaciones web.
FUFP ayuda a testers de seguridad, bug bounty hunters y desarrolladores a:

* Identificar validaciones débiles de tipo de archivo
* Probar implementaciones de listas negras / listas blancas
* Detectar problemas de confianza en el tipo MIME
* Descubrir inconsistencias en el parseo de extensiones
* Evaluar riesgos de ejecución del lado del servidor
* Analizar el manejo y la extracción de archivos comprimidos

FUFP está pensado para **pruebas manuales**, **automatización** y **fines educativos**.

---

## 📁 Estructura de Directorios

```
FUFP/
├── fufp.py              # Más información sobre este archivo abajo
├── images/              # Formatos de imagen, polyglots, trucos EXIF y de headers
├── documents/           # Formatos de texto y documentos
├── scripts/             # Lenguajes de scripting y del lado del cliente
├── web/                 # Formatos relacionados con la web (HTML, SVG, XML, CSS)
├── server_side/         # Extensiones ejecutadas del lado del servidor
├── bypass_techniques/   # Intentos de bypass de extensiones y codificación
├── binaries/            # Formatos binarios tipo ejecutable
├── archives/            # Archivos comprimidos y contenedores
├── server_configs/      # Archivos relacionados con configuraciones
├── traversal_tests/     # Referencias a payloads de path traversal
├── magic_bytes/         # Confusión de tipo de archivo basada en headers
├── mime_confusion/      # Casos de desajuste de tipo MIME
├── oversized_files/     # Pruebas basadas en tamaño y timing
├── LICENSE
├── README.md
└── README_ES.md
```

---

## Script Generador de FUFP (**fufp.py**)

FUFP incluye un **generador automático en Python** que crea todo el pack de fuzzing de subida de archivos desde cero de forma segura, reproducible y controlada.

El generador está diseñado teniendo en cuenta las **limitaciones de los sistemas de archivos multiplataforma** (Windows/Linux/macOS) y evita crear archivos que no pueden existir en sistemas reales (como bytes nulos crudos en nombres de archivo o caracteres prohibidos). En su lugar, esos casos límite se representan mediante **contenidos de archivo precisos y archivos de texto descriptivos**, asegurando realismo sin romper la portabilidad.

### Uso

<img width="601" height="202" alt="image" src="https://github.com/user-attachments/assets/b9fdf8ca-347d-4205-bee4-6e221850810e" />

### Uso básico

```bash
python fufp.py
```

* Genera el File Upload Fuzz Pack completo
* Directorio de salida: `FUFP`
* Modo seguro (sin payloads activos)
* Salida mínima por consola

---

### Opciones comunes explicadas

* **`-o, --output OUTPUT`**
  Elegí dónde se va a crear el directorio FUFP.
  Ejemplo:

  ```bash
  python fufp.py -o my_fufp_pack
  ```

* **`-v, --verbose`**
  Muestra cada archivo a medida que se crea. Útil para entender qué hace el generador.

  ```bash
  python fufp.py -v
  ```

* **`-q, --quiet`**
  Salida mínima. Sobrescribe el modo verbose si ambos están activados.

  ```bash
  python fufp.py -q
  ```

* **`--enable-dangerous`** ⚠️
  Habilita payloads activos como `eval`, `system` y `exec`.
  **Usar solo para pruebas de seguridad autorizadas.**

  ```bash
  python fufp.py --enable-dangerous
  ```

* **`--version`**
  Muestra la versión del generador y sale.

  ```bash
  python fufp.py --version
  ```

### Uso recomendado

Para la mayoría de los usuarios:

```bash
python fufp.py
```

Para depuración o para aprender cómo (o qué) archivos se generan:

```bash
python fufp.py -v
```

Para adictos al Bug Bounty (lol):

```bash
python genfufp.py -o FUFP-PREMIUM -v --enable-dangerous
```

---

### Características clave

* **Generación determinística**
  Cada ejecución produce la misma estructura, facilitando la reproducibilidad y el control de versiones.

* **Separación estricta entre texto y binario**
  Los archivos se escriben usando el modo correcto (`text` o `binary`) para simular subidas reales.

* **Magic bytes reales**
  Los formatos binarios (PNG, JPEG, PDF, ZIP, PE, ELF, etc.) incluyen headers válidos para probar validaciones basadas en contenido.

* **Seguro por defecto**
  Payloads potencialmente peligrosos (por ejemplo `system`, `exec`, `eval`) están **deshabilitados por defecto** y reemplazados por marcadores inertes.

* **Payloads peligrosos opcionales**
  Testers avanzados pueden habilitarlos explícitamente mediante un flag de línea de comandos.

* **Sin dependencias externas**
  Usa únicamente la librería estándar de Python, garantizando ejecución sencilla en la mayoría de sistemas.

### Propósito

Este script existe para:

* Eliminar el trabajo manual de crear cientos de archivos de prueba
* Garantizar consistencia entre entornos de testing
* Permitir regeneración, auditoría y compartición sencilla del pack

El generador **no es una herramienta de explotación** — es una fábrica de archivos controlada para **pruebas de seguridad autorizadas e investigación**.

---

## 🧪 Qué Prueba Este Pack

### ✔ Filtrado de Extensiones

* Dobles extensiones (`.php.jpg`)
* Variaciones de mayúsculas (`.PhP`, `.PHP`)
* Puntos finales (`.php.`)
* Múltiples puntos (`.php..`, `.php...`)
* Extensiones alternativas de PHP (`.phtml`, `.php5`, `.phar`, etc.)

### ✔ Validación de Tipo MIME

* Desajustes de Content-Type
* Confianza en headers MIME enviados por el cliente
* Problemas de sniffing MIME del lado del servidor

### ✔ Magic Bytes

* Headers válidos con extensiones peligrosas
* Ejecutables disfrazados de imágenes o documentos
* Payloads tipo polyglot

### ✔ Manejo de Archivos Comprimidos

* ZIPs que contienen scripts o archivos de configuración
* Comportamiento de extracción y validación
* Contenido anidado o engañoso

### ✔ Riesgos de Ejecución en el Servidor

* Extensiones PHP, ASP, JSP, CFML y relacionadas
* Directorios de subida mal configurados
* Permisos de ejecución incorrectos

### ✔ Manejo de Tamaño y Recursos

* Subidas sobredimensionadas
* Simulación de timeouts
* Archivos con metadatos pesados

> Tené en cuenta que este repositorio es seguro para GitHub; algunos archivos de prueba son más peligrosos, por eso existe el flag `--enable-dangerous` en el generador (más info arriba).

---

## 🚀 Uso

### Pruebas Manuales

1. Seleccioná archivos relevantes de FUFP
2. Subilos mediante la funcionalidad de upload del objetivo
3. Observá:

   * Respuestas del servidor
   * Aceptación o rechazo del archivo
   * Cambios de nombre
   * Comportamiento de ejecución o renderizado

### Pruebas Automatizadas

FUFP puede integrarse en:

* Scripts de fuzzing personalizados
* Pipelines de CI
* Flujos de testing de subida en Burp / ZAP

---

## 🔐 Seguridad y Alcance

* Los archivos son **no destructivos**
* Los ejecutables contienen **solo headers**, no malware real
* Los payloads peligrosos están deshabilitados por defecto
* Diseñado para evitar daños accidentales

Aun así, **nunca subas estos archivos a sistemas que no sean tuyos o para los que no tengas permiso explícito**.

---

## ⚠️ Descargo de Responsabilidad Legal

Este proyecto se proporciona **exclusivamente con fines educativos y de pruebas de seguridad autorizadas**.

El autor **no se responsabiliza por el mal uso**, daños o actividades ilegales derivadas del uso de este repositorio.

Al usar FUFP, aceptás cumplir con todas las leyes y regulaciones aplicables.

---

## 🧠 ¿Para Quién es Esto?

* Bug bounty hunters
* Pentesters
* Investigadores de seguridad
* Desarrolladores web probando defensas de subida
* Estudiantes aprendiendo seguridad web

---

## 📌 Notas

* **No es un repositorio de malware**
* No se incluyen exploits reales
* El enfoque está en **detección**, **validación** y **testing defensivo**

---

## ⭐ Contribuir

Los pull requests son bienvenidos si:

* Agregan nuevos tipos de archivo relevantes
* Mejoran la cobertura de bypass
* Mantienen el pack seguro y ético

---

Hecho con <3 por URDev
