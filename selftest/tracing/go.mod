module github.com/grantseltzer/libbpfgoselftest/perfbuffers

go 1.18

require github.com/grantseltzer/libbpfgo v0.2.1-libbpf-0.4.0

require (
	github.com/grantseltzer/libbpfgo/helpers v0.0.0-20220919184217-8ef1425cccdf // indirect
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015 // indirect
)

replace github.com/grantseltzer/libbpfgo => ../../
