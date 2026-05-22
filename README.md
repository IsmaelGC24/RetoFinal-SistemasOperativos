# RetoFinal-SistemasOperativos

EAFIT

# Ejecutar

## Make

´
# 1. Crear un archivo de prueba
echo "AAAAAAAAAAAABBBBBBBBCCCCCCCC texto de prueba" > prueba.txt

# 2. Cifrar y comprimir (te pedirá una llave en la terminal)
./editor write prueba_cifrada.bin < prueba.txt

# 3. Descifrar y descomprimir (usa la misma llave)
./editor read prueba_cifrada.bin

# 4. Verificar que los datos son idénticos
./editor read prueba_cifrada.bin > recuperado.txt
diff prueba.txt recuperado.txt && echo "✓ Integridad OK"


´