.PHONY: clean build integration-test

clean:
	rm -rf source-severity source-severity.tar.gz

build:
	go build -o source-severity .

tarball: build
	tar czvf source-severity.tar.gz plugin.yaml source-severity

test: 
	go test .

integration-test: build
	bash scripts/integration-test.sh
