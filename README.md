# TP_PROTOS – Servidor SOCKS5 + Cliente de Management

Este proyecto implementa:

- Un **servidor proxy SOCKS5** no bloqueante (`bin/socks5d`), con soporte de autenticación RFC 1929 y canal de management propio.
- Un **cliente de management en C** (`bin/client`) para administrar el servidor (usuarios, estadísticas, método de autenticación, auditoría, etc.).
- Scripts de prueba y stress en `tools/`.

## 1. ¿Cómo compilar?

Desde la raíz del proyecto:

```bash
make clean      # Limpia binarios previos
make all        # Compila servidor 
make client     # Compila el cliente
make test       # (Opcional) Compila y ejecuta tests unitarios
```

Esto genera:

- `bin/socks5d` – Servidor SOCKS5 + management
- `bin/client`  – Cliente de management en C

Los tests unitarios se generan (y ejecutan) en `bin/test/*` cuando se usa `make test`.

---
## 2. ¿Cómo correr el servidor SOCKS5?

Sintaxis básica:

```bash
./bin/socks5d [opciones]
```

Opciones más importantes:

- `-l <SOCKS_ADDR>`  Dirección donde escucha SOCKS5 (default `0.0.0.0`)
- `-p <SOCKS_PORT>`  Puerto SOCKS5 (default `1080`)
- `-L <CONF_ADDR>`   Dirección del canal de management (default `127.0.0.1`)
- `-P <CONF_PORT>`   Puerto de management (default `8080`)
- `-u <user:pass>`   Agrega usuario (puede repetirse)
- `-N`               Deshabilita disectors
- `-v`               Muestra versión y termina

Ejemplo mínimo:

```bash
./bin/socks5d
```

Ejemplo con usuarios explícitos:

```bash
./bin/socks5d -l 0.0.0.0 -p 1080 -L 127.0.0.1 -P 8080 \
  -u admin:0000 -u tincho:1234
```

Usuario admin por defecto (si no se sobreescribe con `-u`):

- Usuario: `admin`
- Contraseña: `0000`

---
## 3. ¿Cómo usar el proxy SOCKS5?

Con `curl` sin auth (está permitido por configuración):

```bash
curl -x "socks5h://127.0.0.1:1080" http://example.com
```

Con autenticación usuario/contraseña:

```bash
curl -x "socks5h://admin:0000@127.0.0.1:1080" http://example.com
```

Configuración típica por defecto (usando: def def):

- SOCKS Host: `127.0.0.1`
- Port: `1080`
- SOCKS v5

---
## 4. Cliente de management (C)

### 4.1. ¿Qué es?

Un cliente en C para el protocolo de management del servidor. Permite:

- Autenticarse con usuario/contraseña.
- Listar, agregar y eliminar usuarios.
- Cambiar el rol (admin/user) de un usuario.
- Consultar estadísticas del servidor.
- Ver el historial de actividad de un usuario.
- Consultar y cambiar el método de autenticación por defecto.

### 4.2. Ejecución

Sintaxis:

```bash
./bin/client <host> <port> <username> <password> <command> [args]
```

Atajo: usar `def` como host o puerto para tomar `localhost` y `8080`:

```bash
./bin/client def def admin 0000 stats
```

Comandos principales (y alias):

- `help` / `-h`                  – Muestra ayuda local.
- `users`                        – Lista usuarios.
- `stats`                        – Muestra estadísticas del servidor.
- `add <UNAME> <PWD>`            – Agrega usuario (admin only).
- `del <UNAME>`                  – Elimina usuario (admin only).
- `chrol <UNAME> <admin|user>`   – Cambia rol (admin only).
- `audit <UNAME>`                – Muestra auditoría del usuario (admin only).
- `gauth` / `sauth <modo>`       – Get/set método de auth por defecto.

Ejemplos:

```bash
# Listar usuarios
./bin/client def def admin 0000 users

# Crear usuario normal
./bin/client def def admin 0000 add tincho 1234

# Ver actividad de un usuario
./bin/client def def admin 0000 audit tincho
```

---
## 5. Scripts de stress y pruebas (tools/)

Todos los scripts están en `tools/`. Antes de usarlos:

```bash
chmod +x tools/*.sh
```

Algunos scripts relevantes:

- `tools/auth_test.sh`  – Prueba rápida de handshake + auth SOCKS5.
- `tools/testConections.sh` – Lanza ~500 conexiones vía `curl` con auth.
- `tools/integratedTest.sh` – Stress test integrado (usa `CONNECTIONS` y `CONCURRENCY` configurables).

Ejecución típica del integrated test (con el servidor en `127.0.0.1:1080`):

```bash
./tools/integratedTest.sh
```

Genera:

- `tools/stress_results_YYYYMMDD_HHMMSS.log`
- `tools/stress_summary_YYYYMMDD_HHMMSS.txt`

---
## 6. Notas

- El cliente de management requiere autenticación para todos los comandos (salvo `help`).
- El servidor debe estar corriendo y accesible en la IP/puerto configurados antes de usar `bin/client` o los scripts de stress.
- Para detalles internos (FSM, parsers, protocolo de management), ver el informe del TP.
