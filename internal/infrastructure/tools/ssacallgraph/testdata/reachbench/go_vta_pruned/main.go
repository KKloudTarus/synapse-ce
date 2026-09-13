package main

type greeter interface{ greet() }

type safeImpl struct{}

func (safeImpl) greet() {}

type dangerImpl struct{}

func (dangerImpl) greet() { danger() }

func danger() {}

func main() {
	var g greeter = safeImpl{}
	g.greet()
}
