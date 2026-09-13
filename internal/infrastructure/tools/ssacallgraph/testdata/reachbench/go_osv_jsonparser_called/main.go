package main

import "github.com/buger/jsonparser"

func main() {
	_ = jsonparser.Delete([]byte(`{"property":"value"}`), "property")
}
