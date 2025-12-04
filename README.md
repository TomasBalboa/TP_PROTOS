# TP_PROTOS - Servidor Proxy SOCKS5

Implementación de un servidor proxy SOCKS5 según RFC 1928 con autenticación de usuario/contraseña (RFC 1929).

## Requisitos

- Sistema operativo: Linux/macOS
- Compilador: `gcc` con soporte para C11
- Estándares: ISO/IEC 9899:2011 (C11), IEEE Std 1003.1-2008 (POSIX)

## Compilación

Para compilar el proyecto:

```bash
make
```

Para limpiar los archivos compilados:

```bash
make clean
```

El ejecutable se generará en `bin/socks5d`.

## Uso

### Sintaxis básica

```bash
./bin/socks5d [OPCIONES]
```

### Opciones disponibles

| Opción | Parámetro | Descripción | Por defecto |
|--------|-----------|-------------|-------------|
| `-h` | - | Imprime ayuda y termina | - |
| `-l` | SOCKS_ADDR | Dirección IP donde escucha el servidor SOCKS | `0.0.0.0` |
| `-L` | CONF_ADDR | Dirección IP donde escucha el servidor de configuración | `127.0.0.1` |
| `-N` | - | Deshabilita passwords disectors | Habilitado |
| `-p` | SOCKS_PORT | Puerto TCP donde escucha el servidor SOCKS | `1080` |
| `-P` | CONF_PORT | Puerto TCP donde escucha el servidor de configuración | `8080` |
| `-u` | USER:PASS | Usuario y contraseña para autenticación (puede repetirse) | - |
| `-v` | - | Imprime información sobre la versión y termina | - |

### Ejemplos

#### Ejecutar con configuración por defecto
```bash
./bin/socks5d
```
El servidor escuchará en `0.0.0.0:1080` sin autenticación.

#### Ejecutar con IP y puerto específicos
```bash
./bin/socks5d -l 127.0.0.1 -p 9090
```
El servidor escuchará solo en `127.0.0.1:9090`.

#### Ejecutar con autenticación
```bash
./bin/socks5d -l 127.0.0.1 -p 1080 -u admin:password123 -u user:pass456
```
El servidor aceptará dos usuarios: `admin` con contraseña `password123` y `user` con contraseña `pass456`.

#### Configuración completa
```bash
./bin/socks5d -l 0.0.0.0 -p 1080 -L 127.0.0.1 -P 8080 -u admin:secret
```
- Servidor SOCKS5: `0.0.0.0:1080` (todas las interfaces)
- Servidor de configuración: `127.0.0.1:8080` (solo local)
- Usuario: `admin` con contraseña `secret`

## Probar el servidor

### Con curl (usando SOCKS5)
```bash
curl --socks5 127.0.0.1:1080 http://example.com
```

### Con autenticación
```bash
curl --socks5 admin:password123@127.0.0.1:1080 http://example.com
```

### Configurar navegador
1. Firefox: Preferences → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1`
3. Port: `1080`
4. SOCKS v5

## Logs

Los logs del servidor se guardan en el directorio `log/` con el formato `DD-MM-YYYY.log`.
