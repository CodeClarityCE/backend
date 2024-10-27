for f in ./plugins/* ; do
	cd $f
	cp ../../.cloud/docker/config/.netrc .cloud/docker/config/.netrc
	make build-prod
	cd -
done

for f in ./services/* ; do
	cd $f
	cp ../../.cloud/docker/config/.netrc .cloud/docker/config/.netrc
	make build-prod
	cd -
done