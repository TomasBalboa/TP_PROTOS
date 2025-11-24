
```bash
# Compilar todo el proyecto
make

# Compilar solo el servidor
make server

# Compilar solo el cliente administrativo
make client

# Compilar con información de debug
make debug

# Limpiar archivos generados
make clean
```


### Servidor Principal
```bash
# Ejecutar con configuración por defecto
./bin/socks5d

# Especificar puertos personalizados
./bin/socks5d -p 1080 -a 9090

# Configuración completa
./bin/socks5d --socks-port 1080 --admin-port 9090 --bind 0.0.0.0 --max-connections 1000
```

### Opciones de Línea de Comandos
- `-p, --socks-port PORT`: Puerto para el proxy SOCKS (default: 1080)
- `-a, --admin-port PORT`: Puerto para administración (default: 9090)  
- `-b, --bind ADDRESS`: Dirección IP para bind (default: 0.0.0.0)
- `-m, --max-connections N`: Máximo número de conexiones (default: 1000)
- `-l, --log-file FILE`: Archivo de log (default: socks5d.log)
- `-u, --users-file FILE`: Archivo de usuarios (default: users.txt)
- `-h, --help`: Mostrar ayuda
- `-v, --version`: Mostrar versión
