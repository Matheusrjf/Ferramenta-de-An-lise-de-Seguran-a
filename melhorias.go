package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type Rule struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    int    `json:"severity"`
	Suggestion  string `json:"suggestion"`
	Regex       *regexp.Regexp
}

type Finding struct {
	File       string
	Line       int
	Rule       Rule
}

var rules []Rule

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Uso: gosecscan <diretório ou arquivo> <rules.json>")
		return
	}

	target := os.Args[1]
	rulesFile := os.Args[2]

	if err := loadRules(rulesFile); err != nil {
		fmt.Println("Erro ao carregar regras:", err)
		return
	}

	findings := scanTarget(target)

	if len(findings) == 0 {
		fmt.Println("[✓] Nenhuma vulnerabilidade conhecida encontrada!")
		return
	}

	fmt.Println("[!] Vulnerabilidades encontradas:")
	totalScore := 0
	for _, f := range findings {
		fmt.Printf("\nArquivo: %s (Linha %d)\n", f.File, f.Line)
		fmt.Printf("→ Descrição: %s\n", f.Rule.Description)
		fmt.Printf("→ Severidade: %d\n", f.Rule.Severity)
		fmt.Printf("→ Sugestão: %s\n", f.Rule.Suggestion)
		totalScore += f.Rule.Severity
	}

	fmt.Println("\n=== RESUMO DE RISCO ===")
	fmt.Printf("Pontuação total: %d\n", totalScore)
	switch {
	case totalScore == 0:
		fmt.Println("🟢 Seguro")
	case totalScore <= 7:
		fmt.Println("🟡 Atenção")
	default:
		fmt.Println("🔴 Crítico")
	}
}

func loadRules(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	for i := range rules {
		rules[i].Regex = regexp.MustCompile(rules[i].Pattern)
	}
	return nil
}

func scanTarget(target string) []Finding {
	var results []Finding
	info, err := os.Stat(target)
	if err != nil {
		return results
	}
	if info.IsDir() {
		filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() && isCodeFile(path) {
				results = append(results, scanFile(path)...)
			}
			return nil
		})
	} else {
		results = append(results, scanFile(target)...)
	}
	return results
}

func isCodeFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".go" || ext == ".js" || ext == ".py" || ext == ".java"
}

func scanFile(path string) []Finding {
	var results []Finding
	file, err := os.Open(path)
	if err != nil {
		return results
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text()
		for _, rule := range rules {
			if rule.Regex.MatchString(line) {
				results = append(results, Finding{
					File: path,
					Line: lineNumber,
					Rule: rule,
				})
			}
		}
		lineNumber++
	}
	return results
}
