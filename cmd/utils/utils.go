package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Move the generated keys to the correct location
func MoveKeys() (err error) {
	err = os.Rename("public.pem", "encryptor/public.pem")
	if err != nil {
		return err
	}

	err = os.Rename("private.pem", "decryptor/private.pem")
	if err != nil {
		return err
	}

	return nil
}

// CheckGoInstalled checks if go is installed on the system
func CheckGoInstalled() (bool, error) {
	cmd := exec.Command("go", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	if strings.Contains(string(output), "go version") {
		return true, nil
	}
	return false, nil
}

// CheckGarbleInstalled checks if garble is installed on the system
func CheckGarbleInstalled() (bool, error) {
	cmd := exec.Command("garble", "version")
	if err := cmd.Run(); err != nil {
		return false, err
	}
	return true, nil
}

// Build the projects using garble
func BuildProject(projectPath string, outputPath string) error {
	// Change the working directory to the project directory
	if err := os.Chdir(projectPath); err != nil {
		return err
	}
	// Run the garble build command
	cmd := exec.Command("garble", "-literals", "-tiny", "build", ".")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Move the built .exe file to the output directory
	files, err := filepath.Glob("*.exe")
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := os.Rename(file, filepath.Join(outputPath, file)); err != nil {
			return err
		}
	}

	// Change the working directory back to the original directory
	if err := os.Chdir(".."); err != nil {
		return err
	}

	return nil
}
