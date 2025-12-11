#test para SOCKSv5 HELLO + AUTH (user/pass)
# PRUEBA: ./auth_test.sh [host] [port]
#No estoy encontrando otra forma más sencillade hacer esto sin usar netcat y sleep
#Pido ayuda a GPT

HOST=${1-localhost}
PORT=${2-1080}

# HELLO then AUTH with small sleep between
echo "Sending HELLO + AUTH to ${HOST}:${PORT}"
{ printf '\x05\x01\x02'; sleep 0.1; printf '\x01\x05admin\x040000'; } | nc -N ${HOST} ${PORT} | xxd -p -c 256

echo "Done"

#CONVERTÍ DE WINDOWS A UNIX CON:
# dos2unix tools/auth_test.sh 2>/dev/null || sed -i 's/\r$//' tools/auth_test.sh
#Por ahora explicación:
#El primer printf envía el HELLO:
#- \x05: versión SOCKS5
#- \x01: número de métodos de autenticación soportados (1)
#- \x02: método de autenticación (0x02 = username/password)
#El segundo printf envía el AUTH:
#- \x01: versión del subprotocolo de autenticación (1)
#- \x04: longitud del nombre de usuario (4)
#- user: nombre de usuario (4 bytes)
#- \x04: longitud de la contraseña (4)
#- pass: contraseña (4 bytes)
#El comando nc conecta al servidor SOCKS5 en el host y puerto especificados
#envia primero el HELLO y luego el AUTH, con una pequeña pausa entre ambos para asegurar que el servidor 
#los procese correctamente.
#La salida la paso por xxd así tengo la respuesta en hexa.