FROM gcr.io/oss-fuzz-base/base-builder-go:v1@sha256:752250ed44cd0d770d1c71dc12925c50dff454db2ea7bc019f43782cbd610de2
COPY . $SRC/go-avscan
WORKDIR $SRC/go-avscan
COPY .clusterfuzzlite/build.sh $SRC/
