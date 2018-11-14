#!/bin/sh

rmfile=1
tarbox=2
chmodfile=3
runfile=4
doshellstatus=0

echo "start run tarscript.sh"

if [ $rmfile == $1 ]
then

echo "chmod -R 777 $2"
chmod -R 777 $2
echo $?

echo "rm $2"
rm $2
echo $?

elif [ $tarbox == $1 ]
then

echo "chmod -R 777 $2"
chmod -R 777 $2
echo $?

echo "tar -zxvf $2 -C $3"
tar -zxvf $2 -C $3
echo $?

elif [ $chmodfile == $1 ]
then

echo "chmod -R 777 $2"
chmod -R 777 $2
echo $?

elif [ $runfile == $1 ]
then

echo "killall -9 $2"
killall -9 $2
echo $?

echo "chmod -R 777 $3"
chmod -R 777 $3
echo $?

echo "run $3"
$3
echo $?

fi 

echo "stop run tarscript.sh"
