package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: gosecscan <diretório ou arquivo>")
		return
	}

	target := os.Args[1]
	fmt.Println("[*] Iniciando análise de segurança em:", target)

	vulnerabilities := ScanTarget(target)
	if len(vulnerabilities) == 0 {
		fmt.Println("[+] Nenhuma vulnerabilidade conhecida encontrada!")
	} else {
		fmt.Println("[!] Vulnerabilidades encontradas:")
		for _, v := range vulnerabilities {
			fmt.Printf("Arquivo: %s (Linha %d): %s\n", v.File, v.Line, v.Pattern)
		}
	}
}
