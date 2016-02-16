#/bin/bash
# Jool Compile se encarga de preparar cada version de kernel de Linux (make modules_prepare)
# para compilar Jool. El objetivo de este algoritmo es probar la compilacion de Jool en
# todas las versiones del kernel de linux que se encuentren en el repositorio oficial en Github.
# Autor: cdeleon - Nic Mx

#Substute with where your git directory is:
GIT_DIR="/home/jool/git"
JOOL_DIR=$(echo ${PWD%/test/compilation_test})
LINUX_DIR="$GIT_DIR/linux"
LINUX_GIT="https://github.com/torvalds/linux.git"

JOOL_LOG=$(echo $PWD/jool-compile-log.log)
RESULT_LOG=$(echo $PWD/result-compile-log.log)

# Ir al directorio de linux-git
if [ ! -d $LINUX_DIR ]; then
	cd $GIT_DIR
	git clone $LINUX_GIT
fi
cd $LINUX_DIR

>$JOOL_LOG
>$RESULT_LOG

# Actualizamos el repositorio git de linux
make clean
rm .config
git clean -f
git checkout master
git pull

# Hacer un arreglo con todas las versiones del kernel a usar para compilar
kernels=($(git tag|grep -v \-));
echo
echo "Comienza..."
for a in ${kernels[@]}; do
	# No soportamos versiones anteriores a la 3.2, por lo que saltamos las 2.x para ahorrar tiempo
	if [[ "$a" == *"v2."* ]]; then
	echo "No soportamos version $a, saltando..."
	continue
	fi

	# Ir al directorio de linux-git
	cd $LINUX_DIR

	echo -e "\n*********************Usando la version $a del kernel***********************" | tee -a $JOOL_LOG $RESULT_LOG
	echo "Haciendo el Checkout..." | tee -a $RESULT_LOG
	# Creamos folder y checkout de la version
	git checkout $a
	echo "Checkout completo!" | tee -a $RESULT_LOG

	echo "Compilando modulos del kernel $a..."|tee -a $JOOL_LOG $RESULT_LOG

	yes ""|make oldconfig >/dev/null 2>&1
	make modules_prepare >/dev/null 2>&1

	if [ $? -eq 0 ]
	then
		echo "Kernel $a compilado (creo)"|tee -a $JOOL_LOG $RESULT_LOG
	else
		echo "Quizas hubo un error compilando el kernel"|tee -a $JOOL_LOG $RESULT_LOG
	fi

	# Moverme al directorio mod de jool
	cd $JOOL_DIR/mod

	# Apuntar los Makefile al directorio donde tengo los kernels compilados
	sed -ri 's;(^KERNEL_DIR :=).*;\1 '"$LINUX_DIR"';' ./stateful/Makefile ./stateless/Makefile

	echo -e "\nCompilando jool con kernel $a" | tee -a $JOOL_LOG $RESULT_LOG
	# Compilar
	make 2>&1 | tee -a $JOOL_LOG | grep --line-buffered '\<[Ee]rror\>'
	if [ ${PIPESTATUS[0]} -eq 0 ]
	then
		echo "Compilacion exitosa!" | tee -a $RESULT_LOG
	else
		echo "Error en la compilacion." | tee -a $RESULT_LOG
	fi
	make clean>/dev/null 2>&1
	cd $LINUX_DIR
	make clean>/dev/null 2>&1
	rm .config
	git clean -f
done

