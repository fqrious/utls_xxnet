go build -buildmode=c-shared -o build/pyutls.so .
cp build/pyutls.so python/
DIR=$PWD

cd python
python3 test_initial.py
