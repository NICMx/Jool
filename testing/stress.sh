i=1
initial=`date +%s`
actual=`date +%s`
while [ $(($actual - $initial)) -le 60 ] 
do
	./ct.out fec0::3 "abcdefghijklmnopqrstuvwxyz"
	echo "Caso : $i - $(($actual - $initial))"
	i=`expr $i + 1`
	actual=`date +%s`
done
