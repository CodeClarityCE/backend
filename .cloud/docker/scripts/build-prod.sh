for f in ./plugins/* ; do
	cd $f
	cp -r ../../.cloud/docker/config .cloud/docker/config
	make build-prod
	cd -
done

for f in ./services/* ; do
	cd $f
	cp -r ../../.cloud/docker/config .cloud/docker/config
	make build-prod
	cd -
done