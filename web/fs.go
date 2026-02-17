package web

import "embed"

//go:embed templates/index.html
var Content embed.FS
