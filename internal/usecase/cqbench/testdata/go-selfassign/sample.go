package sample

type Config struct {
	Name string
	Port int
}

func (c *Config) Sync() {
	c.Name = c.Name
}
