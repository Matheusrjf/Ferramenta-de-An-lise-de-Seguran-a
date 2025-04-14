package main

import (
	"bufio"
	"os"
	"path/filepath"
)

type Vulnerability struct {
	File    string
	Line    int
	Pattern string
}

func ScanTarget(target string) []Vulnerability {
	var results []Vulnerability

	fileInfo, err := os.Stat(target)
	if err != nil {
		return results
	}

	if fileInfo.IsDir() {
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

func scanFile(path string) []Vulnerability {
	var results []Vulnerability

	file, err := os.Open(path)
	if err != nil {
		return results
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range riskyPatterns {
			if pattern.MatchString(line) {
				results = append(results, Vulnerability{
					File:    path,
					Line:    lineNumber,
					Pattern: pattern.String(),
				})
			}
		}
		lineNumber++
	}

	return results
}
