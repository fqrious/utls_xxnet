go build -buildmode=c-shared -o build/pyutls.so . || exit
cp build/pyutls.so python/
DIR=$PWD

cd python
python3 test_initial.py
