#!/bin/sh
go run window.go common.go > ../../../curve/window_amd64.s
go run edwards_vector.go common.go > ../../../curve/edwards_vector_amd64.s
