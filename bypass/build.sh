#!/bin/bash

# компиляция всех атак
echo "компиляция атак..."

# Java атаки
javac -cp . *.java

# C атака
make clean && make

# создание jar файлов
echo "создание jar файлов..."

# kernelwant
jar cfe kernelwant.jar kernelwant kernelwant.class

# slowris
jar cfe slowris.jar slowris slowris.class

# очистка временных файлов
rm *.class

echo "готово!"
echo "kernelwant: java -jar kernelwant.jar <targetIP> <targetPort> <duration> <threadCount>"
echo "slowris: java -jar slowris.jar <targetHost> <targetPort> <duration> <threadCount>"
echo "aeza_bypass: sudo ./aeza_bypass <targetIP> <targetPort> <duration> <threadCount>"
