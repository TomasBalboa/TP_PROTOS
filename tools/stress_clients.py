#Test de stress --> ver si soporto muchas conexiones concurrentes (mínimo 500)
# Asyncio stress test: open N concurrent SOCKS5 client connections, do HELLO+AUTH and keep them open.
#Corremos el serv --> ./bin/socks5d -p 9090
#Nos fijamos el lim de fds con: ulimit -n (en este caso me dió: 1048576 --> no lo aumento)
#LUego, ejecuto la PRUEBA: python3 tools/stress_clients.py [num_clients] [host] [port] [hold_seconds]
#En nuestro caso vamos a usar: python3 tools/stress_clients.py 500 127.0.0.1 9090 30
#Cada cliente debería imprimir algo del estilo:
#0 reply 050201
#1 reply 050201
#... 
#la primera prueba fue exitosa, logré abrir 500 conexiones concurrentes (se abrieron correctamente, no en orden)
#la segunda falló, tuvimos un segmentation fault, por algún motivo cortó en 479
#[HELLO] hello_write fd=479 wrote=2 bytes
# mientras en otra terminal corro el servidor SOCKS5 (ej: ./bin/socks5d -p [portp] )
#Pido ayuda a GPT

import asyncio
import sys

async def client_task(i, host='127.0.0.1', port=9090, hold=30):
    try:
        r, w = await asyncio.open_connection(host, port)
        w.write(b'\x05\x01\x02')  # HELLO (method USER/PASS)
        await w.drain()
        await asyncio.sleep(0.01)
        w.write(b'\x01\x04user\x04pass') # AUTH
        await w.drain()
        data = await r.read(16)
        print(i, 'reply', data.hex())
        # hold connection open to count concurrent
        await asyncio.sleep(hold)
        w.close()
        await w.wait_closed()
    except Exception as e:
        print('client', i, 'err', e)

async def main(n=500, host='127.0.0.1', port=9090, hold=30):
    tasks = [asyncio.create_task(client_task(i, host, port, hold)) for i in range(n)]
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    host = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9090
    hold = int(sys.argv[4]) if len(sys.argv) > 4 else 30
    asyncio.run(main(n, host, port, hold))


#explicación de código:
#Este script de Python utiliza la biblioteca asyncio para crear múltiples 
# conexiones concurrentes a un servidor SOCKS5, realiza el saludo HELLO y la autenticación AUTH, y mantiene las conexiones 
# abiertas durante un tiempo especificado. El número de clientes, el host, el puerto y el tiempo de espera 
# se pueden configurar mediante argumentos de línea de comandos.
# Cada cliente imprime la respuesta del servidor en formato hexadecimal. 
#

#VER COMANDOS:
#Número de conexiones ESTABLISHED al puerto:
#ss -ant | grep 9090 | grep ESTAB | wc -l
# o
#ss -tn state established '( sport = :9090 )' | wc -l
#Ver procesos / fds:
# conexiones por proceso
#ss -p | grep socks5d
# uso de CPU/RAM
#top -p $(pgrep -d',' socks5d)