# Lab 7: Cifrado de Extremo a Extremo (E2EE) - Sistema de Votación Electrónica

## Descripción General

Este proyecto implementa una API básica con Flask y Python que demuestra un sistema de **votación electrónica con cifrado de extremo a extremo (E2EE)**. El cliente y el servidor se comunican de forma segura utilizando criptografía híbrida que combina RSA y AES.

## Instalación

### 1. Instalar dependencias

```powershell
pip install flask pycryptodome requests
```

## Ejecución

### Paso 1: Iniciar el Servidor

Abre una terminal PowerShell en la carpeta del proyecto:

```powershell
python "server.py"
```

**Salida esperada:**
```
Servidor iniciado. Clave pública disponible en /public_key.
 * Running on http://0.0.0.0:5000
```

El servidor estará disponible en `http://127.0.0.1:5000`

### Paso 2: Ejecutar el Cliente (Notebook)

En otra terminal PowerShell o directamente en Jupyter:

```powershell
jupyter notebook L7-TEL252.ipynb
```

O ejecuta directamente en VS Code con la extensión de Jupyter.
