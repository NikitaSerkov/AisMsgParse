package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─── конфигурация ──────────────────────────────────────────────────────────
type Config struct {
	BaseStation string
	Peers       []string
}

func parseConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	var clean []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			clean = append(clean, l)
		}
	}
	if len(clean) < 3 || len(clean)%2 != 1 {
		return nil, fmt.Errorf("invalid config format")
	}
	cfg := &Config{BaseStation: clean[0]}
	for i := 1; i < len(clean)-1; i += 2 {
		server := clean[i]
		port := clean[i+1]
		if _, err := strconv.Atoi(port); err != nil {
			return nil, fmt.Errorf("invalid port %q for server %q", port, server)
		}
		cfg.Peers = append(cfg.Peers, fmt.Sprintf("%s:%s", server, port))
	}
	return cfg, nil
}

// ─── декодирование AIS ─────────────────────────────────────────────────────
const sixBitASCII = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"

type MessageType int

const (
	Unknown MessageType = iota
	PositionReportClassA
	BaseStationReport
	StaticAndVoyageRelatedData
	AidToNavigationReport
)

func (mt MessageType) String() string {
	switch mt {
	case PositionReportClassA:
		return "1-3"
	case BaseStationReport:
		return "4"
	case StaticAndVoyageRelatedData:
		return "5"
	case AidToNavigationReport:
		return "21"
	default:
		return "?"
	}
}

type AisMessage struct {
	Encoded     string
	Error       string
	MessageType MessageType
	MMSI        string
	Name        string
	InOut       bool
	Raw         string
}

func DecodeAisSentence(sentence string) *AisMessage {
	msg := &AisMessage{Encoded: sentence, Raw: sentence}

	if len(sentence) == 0 || sentence[0] != '!' {
		msg.Error = "сообщение не начинается с '!'"
		return msg
	}

	starIdx := strings.IndexByte(sentence, '*')
	if starIdx == -1 {
		msg.Error = "нет контрольной суммы"
		return msg
	}
	checksumStr := sentence[starIdx+1:]
	expected, err := strconv.ParseInt(checksumStr, 16, 32)
	if err != nil {
		msg.Error = "неверный формат контрольной суммы"
		return msg
	}
	var xor byte
	for i := 1; i < starIdx; i++ {
		xor ^= sentence[i]
	}
	if int(xor) != int(expected) {
		msg.Error = "ошибка контрольной суммы"
		return msg
	}

	fields := strings.Split(sentence[1:starIdx], ",")
	if len(fields) < 7 {
		msg.Error = "недостаточно полей"
		return msg
	}
	packetHeader := "!" + fields[0]

	if packetHeader != "!AIVDM" && packetHeader != "!AIVDO" &&
		packetHeader != "!ABVDM" && packetHeader != "!ABVDO" {
		msg.Error = "неверный заголовок"
		return msg
	}
	msg.InOut = (packetHeader == "!AIVDM" || packetHeader == "!ABVDM")

	fragment, _ := strconv.Atoi(fields[2])
	if fragment != 1 {
		msg.Error = "фрагмент не первый, пропущен"
		return msg
	}

	numFillBits, _ := strconv.Atoi(fields[6])

	payloadBits, err := decodePayloadToBits(fields[5], numFillBits)
	if err != nil {
		msg.Error = "ошибка декодирования payload: " + err.Error()
		return msg
	}

	if len(payloadBits) < 38 {
		msg.Error = "слишком короткое сообщение для MMSI"
		return msg
	}
	msg.MessageType = parseMessageType(binStrToInt(payloadBits[0:6]))
	msg.MMSI = fmt.Sprintf("%d", binStrToInt(payloadBits[8:38]))

	if msg.Error == "" {
		switch msg.MessageType {
		case AidToNavigationReport:
			if len(payloadBits) >= 163 {
				msg.Name = decodeSixBitString(payloadBits[43:163])
			}
		case StaticAndVoyageRelatedData:
			if len(payloadBits) >= 232 {
				msg.Name = decodeSixBitString(payloadBits[112:232])
			} else {
				msg.Name = "ERROR: short message"
			}
		case BaseStationReport:
			msg.Name = "SABETTA"
		}
	}

	return msg
}

func decodePayloadToBits(encoded string, numFillBits int) (string, error) {
	var bits strings.Builder
	for _, ch := range encoded {
		b := byte(ch) - 48
		if b > 40 {
			b -= 8
		}
		if b > 63 {
			return "", fmt.Errorf("invalid character %c", ch)
		}
		bits.WriteString(fmt.Sprintf("%06b", b))
	}
	payload := bits.String()
	if numFillBits > len(payload) {
		return "", fmt.Errorf("fill bits %d exceed payload length %d", numFillBits, len(payload))
	}
	return payload[:len(payload)-numFillBits], nil
}

func decodeSixBitString(bits string) string {
	var out strings.Builder
	for i := 0; i+6 <= len(bits); i += 6 {
		idx := binStrToInt(bits[i : i+6])
		if idx < 0 || idx >= 64 {
			out.WriteByte('?')
		} else {
			out.WriteByte(sixBitASCII[idx])
		}
	}
	return strings.TrimRight(out.String(), "@ ")
}

func binStrToInt(s string) int {
	var v int
	for _, c := range s {
		v = v<<1 | int(c-'0')
	}
	return v
}

func parseMessageType(v int) MessageType {
	switch v {
	case 1, 2, 3:
		return PositionReportClassA
	case 4:
		return BaseStationReport
	case 5:
		return StaticAndVoyageRelatedData
	case 21:
		return AidToNavigationReport
	default:
		return Unknown
	}
}

// ─── TCP клиент ─────────────────────────────────────────────────────────────
func connectAndRead(addr string, out chan<- string) {
	for {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			log.Printf("[TCP] %s: %v, повтор через 5с", addr, err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("[TCP] подключён к %s", addr)
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			out <- scanner.Text()
		}
		conn.Close()
		log.Printf("[TCP] %s: соединение закрыто", addr)
		time.Sleep(5 * time.Second)
	}
}

// ─── файловый логгер ────────────────────────────────────────────────────────
type FileLogger struct {
	mu   sync.Mutex
	dir  string
}

func NewFileLogger(baseDir, subDir string) *FileLogger {
	dir := filepath.Join(baseDir, subDir)
	os.MkdirAll(dir, 0755)
	return &FileLogger{dir: dir}
}

func (fl *FileLogger) Write(now time.Time, line string) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fname := filepath.Join(fl.dir, now.Format("2006-01-02")+".txt")
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[LOG] ошибка: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s;%s\n", now.Format("15:04:05"), line)
}

// ─── main ────────────────────────────────────────────────────────────────────
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg, err := parseConfig("conf.ini")
	if err != nil {
		log.Fatalf("Ошибка конфигурации: %v", err)
	}
	fmt.Println("AIS Monitor Go, базовая станция:", cfg.BaseStation)

	encodedLogger := NewFileLogger("Archive", "Encoded")
	decodedLogger := NewFileLogger("Archive", "Decoded")

	rawLines := make(chan string, 1024)

	for _, peer := range cfg.Peers {
		go connectAndRead(peer, rawLines)
	}

	go func() {
		for line := range rawLines {
			now := time.Now()

			if len(line) > 0 && line[0] == '$' {
				line = "!" + line[1:]
			}

			fmt.Printf("[RAW] %s\n", line)
			encodedLogger.Write(now, line)

			msg := DecodeAisSentence(line)
			if msg.Error != "" {
				if msg.Error != "фрагмент не первый, пропущен" {
					fmt.Printf("[ERR] %s: %s\n", msg.Error, line)
					decodedLogger.Write(now, fmt.Sprintf("ERROR:%s:%s", msg.Error, line))
				}
				continue
			}

			fmt.Printf("[DEC] %s Type:%s MMSI:%s Name:%q\n",
				now.Format("02.01.06 15:04:05"), msg.MessageType, msg.MMSI, msg.Name)
			decodedLogger.Write(now, fmt.Sprintf("Type:%s;MMSI:%s;Name:%s", msg.MessageType, msg.MMSI, msg.Name))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nЗавершение работы")
}
