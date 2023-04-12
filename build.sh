go build -buildmode=c-shared -ldflags=-w -o build/pyutls.so . || exit
cp build/pyutls.so python/
DIR=$PWD

cd python
python3 test_initial.py
