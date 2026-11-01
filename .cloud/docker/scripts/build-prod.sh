for f in ./plugins/* ; do
	cd $f
	make build-prod BUILD_CONTEXT=../../
	cd -
done

for f in ./services/* ; do
	cd $f
	make build-prod BUILD_CONTEXT=../../
	cd -
done