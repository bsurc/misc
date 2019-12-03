package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	flagAddr := flag.String("addr", "", "address to listen on")
	flagProxy := flag.String("proxy", "", "address to proxy")
	flagAcmeDir := flag.String("acmedir", "/opt/acme", "let's encrypt cache")
	flag.Parse()
	host, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}
	u, err := url.Parse(*flagProxy)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	srv := http.Server{
		Addr:    *flagAddr,
		Handler: proxy,
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(*flagAcmeDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(host),
	}
	go func() {
		log.Fatal(http.ListenAndServe(":http", m.HTTPHandler(nil)))
	}()
	srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}
	srv.TLSConfig.MinVersion = tls.VersionTLS12
	log.Fatal(srv.ListenAndServeTLS("", ""))
}