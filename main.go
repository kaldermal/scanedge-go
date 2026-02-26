package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func colored(text, code string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", code, text)
}

func animatedBanner() {
	lines := []string{
		"░██████╗░█████╗░░█████╗░███╗░░██╗███████╗██████╗░░██████╗░███████╗",
		"██╔════╝██╔══██╗██╔══██╗████╗░██║██╔════╝██╔══██╗██╔════╝░██╔════╝",
		"╚█████╗░██║░░╚═╝███████║██╔██╗██║█████╗░░██║░░██║██║░░██╗░█████╗░░",
		"░╚═══██╗██║░░██╗██╔══██║██║╚████║██╔══╝░░██║░░██║██║░░╚██╗██╔══╝░░",
		"██████╔╝╚█████╔╝██║░░██║██║░╚███║███████╗██████╔╝╚██████╔╝███████╗",
		"╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚══════╝╚═════╝░░╚═════╝░╚══════╝",
		"",
		"ScanEdge Go",
		"by torvalds",
		"",
	}
	for _, line := range lines {
		fmt.Println(colored(line, "1;36"))
		time.Sleep(80 * time.Millisecond)
	}
}

func isPrivateIP(first, second int) bool {
	if first == 10 || first == 127 {
		return true
	}
	if first == 169 && second == 254 {
		return true
	}
	if first == 172 && second >= 16 && second <= 31 {
		return true
	}
	if first == 192 && second == 168 {
		return true
	}
	if first >= 224 {
		return true
	}
	return false
}

func generateRandomIP() string {
	for {
		first := rand.Intn(223) + 1
		second := rand.Intn(256)
		if !isPrivateIP(first, second) {
			third := rand.Intn(256)
			fourth := rand.Intn(254) + 1
			return fmt.Sprintf("%d.%d.%d.%d", first, second, third, fourth)
		}
	}
}

type ScanResult struct {
	IP   string
	Port int
	Open bool
}

func scanPort(ip string, port int, timeout time.Duration) ScanResult {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ScanResult{ip, port, false}
	}
	conn.Close()
	return ScanResult{ip, port, true}
}

type JSONOutput struct {
	Timestamp       string           `json:"timestamp"`
	NumIPsScanned   int              `json:"num_ips_scanned"`
	Ports           []int            `json:"ports"`
	TimeoutSec      float64          `json:"timeout_sec"`
	WorkingIPs      map[string][]int `json:"working_ips"`
	WorkingIPsCount int              `json:"working_ips_count"`
}

func saveResultsJSON(filename string, workingIPs map[string][]int, ports []int, numIPs int, timeout float64) error {
	data := JSONOutput{
		Timestamp:       time.Now().Format("2006-01-02 15:04:05"),
		NumIPsScanned:   numIPs,
		Ports:           ports,
		TimeoutSec:      timeout,
		WorkingIPs:      workingIPs,
		WorkingIPsCount: len(workingIPs),
	}
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

func openFileCrossplatform(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	default:
		fmt.Println("Неизвестная ОС: файл не может быть открыт автоматически.")
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Println(colored(fmt.Sprintf("Не удалось открыть файл: %v", err), "1;31"))
	}
}


func parsePorts(portsRaw string) []int {
	portSet := map[int]struct{}{}
	var ports []int
	for _, part := range strings.Split(portsRaw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			fmt.Printf("Неверный порт: %s\n", part)
			continue
		}
		if p < 1 || p > 65535 {
			fmt.Printf("Порт %d вне диапазона (1-65535) и будет пропущен.\n", p)
			continue
		}
		if _, exists := portSet[p]; !exists {
			portSet[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	return ports
}

func clampTimeout(t float64) float64 {
	if t < 0.1 {
		return 0.1
	}
	if t > 5.0 {
		return 5.0
	}
	return t
}

func main() {
	rand.Seed(time.Now().UnixNano())
	animatedBanner()
	fmt.Println(colored("Scan Edge — сканер публичных IP и портов (для обучения)\n", "1;36"))

	args := os.Args[1:]

	var numIPs int
	var ports []int
	var timeoutSec float64

	if len(args) >= 3 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 1 {
			fmt.Println("Ошибка: первый аргумент (кол-во IP) должен быть целым числом >= 1")
			return
		}
		numIPs = n

		ports = parsePorts(args[1])
		if len(ports) == 0 {
			fmt.Println("Не указано ни одного допустимого порта. Завершение.")
			return
		}

		t, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			fmt.Println("Ошибка: третий аргумент (таймаут) должен быть числом, например 0.5")
			return
		}
		timeoutSec = clampTimeout(t)

		fmt.Printf("Режим аргументов: %d IP, порты %v, таймаут %.2f сек\n\n", numIPs, ports, timeoutSec)
	} else {
		reader := bufio.NewReader(os.Stdin)

		readInput := func(prompt string) string {
			fmt.Print(prompt)
			line, _ := reader.ReadString('\n')
			return strings.TrimSpace(line)
		}

		unlimited := false
		numIPs = 0

		for {
			raw := readInput("Сколько IP-адресов сгенерировать? (1-1000): ")
			if strings.ToLower(raw) == ".unl" {
				unlimited = true
				fmt.Println(colored("Код активирован — лимит снят!", "1;33"))
				time.Sleep(1 * time.Second)
				break
			}
			n, err := strconv.Atoi(raw)
			if err != nil {
				fmt.Println("Ошибка: введите целое число")
				continue
			}
			if n < 1 || n > 1000 {
				fmt.Println("Введите число от 1 до 1000")
				continue
			}
			numIPs = n
			break
		}

		if unlimited {
			for {
				raw := readInput("Сколько IP-адресов сгенерировать?: ")
				n, err := strconv.Atoi(raw)
				if err != nil {
					fmt.Println("Ошибка: введите целое число")
					continue
				}
				if n < 1 {
					fmt.Println("Введите положительное число")
					continue
				}
				numIPs = n
				break
			}
		}

		ports = parsePorts(readInput("Укажите порты (через запятую, например 80,443,22): "))
		if len(ports) == 0 {
			fmt.Println("Не указано ни одного допустимого порта. Завершение.")
			return
		}

		timeoutSec = 1.0
		raw := readInput("Таймаут подключения (сек, рекомендуемо 0.5–2): ")
		if t, err := strconv.ParseFloat(raw, 64); err == nil {
			timeoutSec = t
		} else {
			fmt.Println("Некорректное значение, используется таймаут по умолчанию = 1.0")
		}
		timeoutSec = clampTimeout(timeoutSec)
	}

	timeout := time.Duration(timeoutSec * float64(time.Second))

	fmt.Printf("\nГенерация %d IP и сканирование портов %v...\n\n", numIPs, ports)

	ips := make([]string, numIPs)
	for i := range ips {
		ips[i] = generateRandomIP()
	}

	type task struct {
		ip   string
		port int
	}

	total := numIPs * len(ports)
	tasks := make(chan task, total)
	results := make(chan ScanResult, total)

	for _, ip := range ips {
		for _, port := range ports {
			tasks <- task{ip, port}
		}
	}
	close(tasks)

	workers := 500
	if total < workers {
		workers = total
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				results <- scanPort(t.ip, t.port, timeout)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var counter int64
	var mu sync.Mutex
	workingIPs := map[string][]int{}
	var allResults []ScanResult

	for res := range results {
		allResults = append(allResults, res)
		n := atomic.AddInt64(&counter, 1)
		if res.Open {
			fmt.Println(colored(fmt.Sprintf("[ОТКРЫТ] %s:%d", res.IP, res.Port), "1;32"))
			mu.Lock()
			workingIPs[res.IP] = append(workingIPs[res.IP], res.Port)
			mu.Unlock()
		}
		if n%100 == 0 || int(n) == total {
			fmt.Printf("Проверено %d/%d комбинаций...\n", n, total)
		}
	}

	_ = allResults

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("scan_results_%s.json", timestamp)
	if err := saveResultsJSON(filename, workingIPs, ports, numIPs, timeoutSec); err != nil {
		fmt.Printf("Ошибка сохранения: %v\n", err)
	}

	fmt.Println("\nРезультаты:")
	fmt.Printf("Проверено: %d IP × %d портов = %s проверок\n", numIPs, len(ports), formatInt(total))
	fmt.Println(colored(fmt.Sprintf("Найдено рабочих IP: %d", len(workingIPs)), "1;32"))
	fmt.Printf("Файл с результатами: %s\n", filename)

	fmt.Println("\nОткрытие файла с результатами...")
	time.Sleep(2 * time.Second)
	openFileCrossplatform(filename)

	fmt.Println("\nПрограмма завершится через 5 секунд...")
	time.Sleep(5 * time.Second)
}

func formatInt(n int) string {
	s := strconv.Itoa(n)
	result := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result += ","
		}
		result += string(c)
	}
	return result
}
