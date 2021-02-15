package drop

import (
	"errors"
	"fmt"
	"github.com/box/kube-iptables-tailer/util"
	"github.com/golang/glog"
	"reflect"
	"strings"
	"time"
)

const fieldSrcIP = "SRC"
const fieldDstIP = "DST"
const fieldProto = "PROTO"
const fieldTCPSYN = "SYN"
const protoTCP = "TCP"
const PacketDropLogTimeLayout = "2006-01-02T15:04:05.000000-07:00"

// PacketDrop is the result object parsed from single raw log containing information about an iptables packet drop.
type PacketDrop struct {
	LogTime  string
	HostName string
	SrcIP    string
	DstIP    string
}

var fieldCount = reflect.ValueOf(PacketDrop{}).NumField()

// Check if PacketDrop is expired
func (pd PacketDrop) IsExpired() bool {
	logTime, err := pd.GetLogTime()
	if err != nil {
		glog.Errorf("Error retrieving log time to check expiration: %+v", err)
		return true // we consider it expired if we cannot parse the time
	}
	curTime := time.Now()
	expiredMinutes := float64(util.GetEnvIntOrDefault(
		util.PacketDropExpirationMinutes, util.DefaultPacketDropExpirationMinutes))
	return curTime.Sub(logTime).Minutes() > expiredMinutes
}

// Get the time object of PacketDrop log time
func (pd PacketDrop) GetLogTime() (time.Time, error) {
	return time.Parse(PacketDropLogTimeLayout, pd.LogTime)
}

// Parse the logs from given channel and insert objects of PacketDrop as parsing result to another channel
func RunParsing(logPrefix string, logChangeCh <-chan string, packetDropCh chan<- PacketDrop) {
	for log := range logChangeCh {
		parseErr := parse(logPrefix, log, packetDropCh)
		if parseErr != nil {
			// report the current error log but continue the parsing process
			glog.Errorf("Cannot parse the log: %s, error: %+v", log, parseErr)
		}
	}
}

// Parse the given log, and insert the result to PacketDrop's channel if it's not expired
func parse(logPrefix, log string, packetDropCh chan<- PacketDrop) error {
	// only parse the required packet drop logs
	if !isRequiredPacketDropLog(logPrefix, log) {
		return nil
	}
	glog.V(4).Infof("Parsing new packet drop: log=%+v", log)
	// parse the log and get an object of PacketDrop as result
	packetDrop, err := getPacketDrop(log)
	if err != nil {
		return err
	}
	// only insert the packetDrop into channel if it's not expired
	if !packetDrop.IsExpired() {
		packetDropCh <- packetDrop
	}

	return nil
}

// Check if a log is a required packet drop containing the given log prefix
func isRequiredPacketDropLog(logPrefix, log string) bool {
	for _, field := range strings.Fields(log) {
		if field == logPrefix {
			return true
		}
	}
	return false
}

// Return a PacketDrop object constructed from given PacketDropLog
func getPacketDrop(packetDropLog string) (PacketDrop, error) {
	// object PacketDrop needs at least 4 different fields
	logFields, err := getPacketDropLogFields(packetDropLog)
	if err != nil {
		return PacketDrop{}, err
	}

	// get log time and host name
	logTime, hostName := logFields[0], logFields[1]

	// get src and dst IPs
	srcIP, err := getFieldValue(logFields, fieldSrcIP)
	if err != nil {
		return PacketDrop{}, err
	}
	dstIP, err := getFieldValue(logFields, fieldDstIP)
	if err != nil {
		return PacketDrop{}, err
	}

	// Ignore TCP packet drops that do not include a SYN flag.
	// Generally IPTables rules for TCP will use conntrack to allow all traffic after the initial 3-way handshake using
	// conntrack. Rules will be applied at a lower precedence which in turn means if we encounter any drops without a
	// SYN it's because of a broken connection and not a disallowed flow.
	if protocol, err := getFieldValue(logFields, fieldProto); err == nil && protocol == protoTCP {
		if !hasField(logFields, fieldTCPSYN) {
			// No SYN flag.
			return PacketDrop{}, errors.New("Ignoring TCP packet without a SYN flag")
		}
	}

	return PacketDrop{
			LogTime:  logTime,
			HostName: hostName,
			SrcIP:    srcIP,
			DstIP:    dstIP},
		nil
}

// Helper function to check and return fields (if there are enough of them) of given PacketDrop log
func getPacketDropLogFields(packetDropLog string) ([]string, error) {
	logFields := strings.Fields(packetDropLog)
	// check if the logFields contain enough information about a packet drop
	if len(logFields) < fieldCount {
		return []string{}, errors.New(fmt.Sprintf("Invalid packet drop: log=%+v", packetDropLog))
	}
	return logFields, nil
}

// Helper function to get the field from log: "... fieldName=1.1.1" returns "1.1.1"
func getFieldValue(logFields []string, fieldName string) (string, error) {
	for _, field := range logFields {
		if strings.HasPrefix(field, fieldName) {
			fieldStrs := strings.Split(field, "=")
			if len(fieldStrs) < 2 {
				return "", errors.New(fmt.Sprintf("Missing value: field=%+v", fieldName))
			}
			return fieldStrs[1], nil

		}
	}
	return "", errors.New(fmt.Sprintf("Missing field=%+v", fieldName))
}

func hasField(logFields []string, fieldName string) bool {
	for _, field := range logFields {
		if field == fieldName || strings.HasPrefix(field, fmt.Sprintf("%s=", fieldName)) {
			return true
		}
	}
	return false
}
