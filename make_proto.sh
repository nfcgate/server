#!/bin/bash

PROTO_IN=protocol/protobuf
PROTO_OUT=plugins

protoc -I=$PROTO_IN --python_out=$PROTO_OUT $PROTO_IN/*.proto
