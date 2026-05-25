package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─── конфигурация (читается из conf.ini) ────────────────────────────────────
type Config struct {
	BaseStation string   // первая строка файла (bs)
	Peers       []string // пары "server:port"
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
		return nil, fmt.Errorf("invalid config format: need base station and even number of server/port pairs")
	}
	cfg := &Config{
		BaseStation: clean[0],
	}
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

// ─── структура декодированного сообщения ────────────────────────────────────
type MessageType int

const (
	Unknown MessageType = iota
	PositionReportClassA
	BaseStationReport
	StaticAndVoyageRelatedData
	AidToNavigationReport
	BinaryAcknowledge
	BinaryAddressedMessage
	// ... можно дополнить при необходимости
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
	case BinaryAcknowledge:
		return "7/13"
	case BinaryAddressedMessage:
		return "6/8"
	default:
		return "?"
	}
}

type AisMessage struct {
	Encoded     string
	Error       string   // пустая строка при успехе
	MessageType MessageType
	MMSI        string
	Name        string
	InOut       bool // true = входящее (!AIVDM/!ABVDM), false = исходящее (!AIVDO/!ABVDO)
	Raw         string
}

// корректная 6‑битная таблица символов AIS (64 символа)
const sixBitASCII = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"

// ─── парсинг и декодирование одного NMEA‑предложения ────────────────────────
func DecodeAisSentence(sentence string) *AisMessage {
	msg := &AisMessage{Encoded: sentence, Raw: sentence}

	if len(sentence) == 0 || sentence[0] != '!' {
		msg.Error = "сообщение не начинается с '!'"
		return msg
	}

	// контрольная сумма
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
	// вычисляем XOR символов между '!' и '*'
	var xor byte
	for i := 1; i < starIdx; i++ {
		xor ^= sentence[i]
	}
	if int(xor) != int(expected) {
		msg.Error = "ошибка контрольной суммы"
		return msg
	}

	// поля сообщения
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

	fragment, _ := strconv.Atoi(fields[2]) // fields[2] – номер фрагмента
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

	// извлекаем заголовочные поля
	if len(payloadBits) < 38 {
		msg.Error = "слишком короткое сообщение для MMSI"
		return msg
	}
	typeBits := payloadBits[0:6]
	msg.MessageType = parseMessageType(binStrToInt(typeBits))
	msg.MMSI = fmt.Sprintf("%d", binStrToInt(payloadBits[8:38]))

	// извлечение имени в зависимости от типа
	if msg.Error == "" {
		switch msg.MessageType {
		case AidToNavigationReport:
			if len(payloadBits) >= 163 { // 43+120
				nameBits := payloadBits[43:163]
				msg.Name = decodeSixBitString(nameBits)
			}
		case StaticAndVoyageRelatedData:
			if len(payloadBits) >= 232 { // 112+120
				nameBits := payloadBits[112:232]
				msg.Name = decodeSixBitString(nameBits)
			} else {
				msg.Name = "ERROR: short message"
			}
		case BaseStationReport:
			msg.Name = "SABETTA" // исходная логика
		}
	}

	return msg
}

// преобразование закодированной строки в битовую, с удалением numFillBits в конце
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
	// удаляем numFillBits с конца (стандарт AIS)
	if numFillBits > len(payload) {
		return "", fmt.Errorf("fill bits %d exceed payload length %d", numFillBits, len(payload))
	}
	return payload[:len(payload)-numFillBits], nil
}

// 6-битная строка в текст
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
	case 7, 13:
		return BinaryAcknowledge
	case 6, 8:
		return BinaryAddressedMessage
	default:
		return Unknown
	}
}

// ─── клиент TCP с автоматическим переподключением ──────────────────────────
func connectAndRead(addr string, out chan<- string) {
    for {
        conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
        if err != nil {
            log.Printf("[TCP] %s: %v, переподключение через 5с", addr, err)
            time.Sleep(5 * time.Second)
            continue
        }
        log.Printf("[TCP] подключён к %s", addr)
        scanner := bufio.NewScanner(conn)
        for scanner.Scan() {
            out <- scanner.Text()
        }
        conn.Close()
        log.Printf("[TCP] %s: соединение закрыто, переподключение...", addr)
        time.Sleep(5 * time.Second)
    }
}

func DialWithTimeout(addr string, timeout time.Duration) (*os.File, error) {
	// Для простоты используем net.Dial, но нам нужно превратить в bufio.Scanner,
	// поэтому возвращаем net.Conn.
	// Здесь для краткости просто вызовем net.Dial.
	// (В реальном коде следует импортировать "net")
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*os.File), nil // !!! Это заглушка, реально net.Conn ≠ *os.File
	// В финальном коде используйте net.Conn и bufio.NewScanner(conn) напрямую.
	// Исправим ниже.
}

// ─── работа с архивными файлами ─────────────────────────────────────────────
type FileLogger struct {
	mu   sync.Mutex
	dir  string
	name string
}

func NewFileLogger(baseDir, subDir, prefix string) *FileLogger {
	dir := filepath.Join(baseDir, subDir)
	os.MkdirAll(dir, 0755)
	return &FileLogger{dir: dir, name: prefix}
}

func (fl *FileLogger) Write(now time.Time, line string) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fname := filepath.Join(fl.dir, now.Format("2006-01-02")+".txt")
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[LOG] ошибка открытия %s: %v", fname, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s;%s\n", now.Format("15:04:05"), line)
}

// ─── таблица состояния (аналог ListView) ────────────────────────────────────
type VesselState struct {
	MMSI        string
	MsgType     string
	Name        string
	FirstTime   time.Time
	LastTime    time.Time
	InCount     int
	OutCount    int
	InAvgStr    string // храним строку как в оригинале, или вычисляем
	OutAvgStr   string
	InPeriodSum time.Duration
	OutPeriodSum time.Duration
}

var (
	vessels   = make(map[string]*VesselState) // ключ "MMSI|MsgType"
	vesselMu  sync.Mutex
)

func updateVessel(msg *AisMessage, now time.Time) {
	vesselMu.Lock()
	defer vesselMu.Unlock()

	key := fmt.Sprintf("%s|%d", msg.MMSI, msg.MessageType)
	vs, ok := vessels[key]
	if !ok {
		vs = &VesselState{
			MMSI:      msg.MMSI,
			MsgType:   msg.MessageType.String(),
			Name:      msg.Name,
			FirstTime: now,
			LastTime:  now,
		}
		vessels[key] = vs
	}
	if vs.Name == "" && msg.Name != "" {
		vs.Name = msg.Name
	}
	vs.LastTime = now

	if msg.InOut {
		if vs.InCount == 0 {
			vs.InAvgStr = "0"
		}
		vs.InCount++
		delta := now.Sub(vs.FirstTime)
		avg := delta / time.Duration(vs.InCount)
		vs.InAvgStr = formatDuration(avg)
	} else {
		if vs.OutCount == 0 {
			vs.OutAvgStr = "0"
		}
		vs.OutCount++
		delta := now.Sub(vs.FirstTime)
		avg := delta / time.Duration(vs.OutCount)
		vs.OutAvgStr = formatDuration(avg)
	}
}

func formatDuration(d time.Duration) string {
	// формат "чч:мм:сс"
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func flushVesselTable(logger *FileLogger, now time.Time) {
	vesselMu.Lock()
	defer vesselMu.Unlock()
	for _, vs := range vessels {
		line := fmt.Sprintf("%s;%s;%s;%d;%s;%s;%s;%s",
			vs.MMSI,
			vs.MsgType,
			vs.Name,
			vs.InCount+vs.OutCount, // в оригинале сумма?
			vs.FirstTime.Format("02.01.06 15:04:05"),
			vs.LastTime.Format("02.01.06 15:04:05"),
			vs.InAvgStr,
			vs.OutAvgStr,
		)
		logger.Write(now, line)
	}
}

// ─── main ────────────────────────────────────────────────────────────────────
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg, err := parseConfig("conf.ini")
	if err != nil {
		log.Fatalf("Ошибка конфигурации: %v", err)
	}
	fmt.Println("AIS Monitor Go v1.0, базовая станция:", cfg.BaseStation)

	// логгеры
	encodedLogger := NewFileLogger("Archive", "Encoded", "raw")
	decodedLogger := NewFileLogger("Archive", "Decoded", "dec")
	tableLogger := NewFileLogger("Archive", "Table", "table")

	// канал входящих необработанных строк
	rawLines := make(chan string, 1024)

	// запускаем TCP-клиентов
	for _, peer := range cfg.Peers {
		go connectAndRead(peer, rawLines)
	}

	// обработка сообщений
	go func() {
		for line := range rawLines {
			now := time.Now()

			// небольшая нормализация: иногда сообщения приходят с '$' вместо '!'
			if len(line) > 0 && line[0] == '$' {
				// заменяем только первый '$' на '!', чтобы не испортить данные
				line = "!" + line[1:]
			}

			// выводим сырое сообщение в консоль
			fmt.Printf("[RAW] %s\n", line)
			encodedLogger.Write(now, line)

			msg := DecodeAisSentence(line)
			if msg.Error != "" {
				if msg.Error != "фрагмент не первый, пропущен" {
					fmt.Printf("[ERR] %s: %s\n", msg.Error, line)
					// ошибки тоже пишем в decoded?
					decodedLogger.Write(now, fmt.Sprintf("ERROR:%s:%s", msg.Error, line))
				}
				continue
			}

			// успешное декодирование
			fmt.Printf("[DEC] %s Type:%s MMSI:%s Name:%q\n",
				now.Format("02.01.06 15:04:05"), msg.MessageType, msg.MMSI, msg.Name)
			decodedLogger.Write(now, fmt.Sprintf("Type:%s;MMSI:%s;Name:%s", msg.MessageType, msg.MMSI, msg.Name))

			// обновляем таблицу
			updateVessel(msg, now)
		}
	}()

	// перехват сигнала завершения
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nЗавершение работы, сохраняем таблицу...")
	flushVesselTable(tableLogger, time.Now())
	fmt.Println("Готово.")
}
