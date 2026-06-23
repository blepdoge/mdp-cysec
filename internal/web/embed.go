package web

import "embed"

//go:embed assets/static/* assets/templates/*
var Assets embed.FS
